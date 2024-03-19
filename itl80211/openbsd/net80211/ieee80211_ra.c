/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/
/*
 * Copyright (c) 2021 Christian Ehrhardt <ehrhardt@genua.de>
 * Copyright (c) 2016, 2021 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2016 Theo Buehler <tb@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_ra.h>

int    ieee80211_ra_next_intra_rate(struct ieee80211_ra_node *, struct ieee80211com *,
        struct ieee80211_node *);
const struct ieee80211_ra_rate * ieee80211_ra_next_rateset(
            struct ieee80211_ra_node *, struct ieee80211com *, struct ieee80211_node *);
int    ieee80211_ra_best_mcs_in_rateset(struct ieee80211_ra_node *,
        const struct ieee80211_ra_rate *);
void    ieee80211_ra_probe_next_rateset(struct ieee80211_ra_node *, struct ieee80211com *,
        struct ieee80211_node *, const struct ieee80211_ra_rate *);
int    ieee80211_ra_next_mcs(struct ieee80211_ra_node *, struct ieee80211com *,
        struct ieee80211_node *);
void    ieee80211_ra_probe_done(struct ieee80211_ra_node *);
int    ieee80211_ra_intra_mode_ra_finished(
        struct ieee80211_ra_node *, struct ieee80211com *, struct ieee80211_node *);
void    ieee80211_ra_trigger_next_rateset(struct ieee80211_ra_node *, struct ieee80211com *,
        struct ieee80211_node *);
int    ieee80211_ra_inter_mode_ra_finished(
        struct ieee80211_ra_node *, struct ieee80211_node *);
int    ieee80211_ra_best_rate(struct ieee80211_ra_node *,
        struct ieee80211_node *);
void    ieee80211_ra_probe_next_rate(struct ieee80211_ra_node *, struct ieee80211com *,
        struct ieee80211_node *);
int    ieee80211_ra_valid_tx_mcs(struct ieee80211_node *, int);
uint32_t ieee80211_ra_valid_rates(struct ieee80211com *,
        struct ieee80211_node *);
int    ieee80211_ra_probe_valid(struct ieee80211_ra_goodput_stats *);

/* We use fixed point arithmetic with 64 bit integers. */
#define RA_FP_SHIFT    21
#define RA_FP_INT(x)    (x ## ULL << RA_FP_SHIFT) /* the integer x */
#define RA_FP_1    RA_FP_INT(1)

/* Multiply two fixed point numbers. */
#define RA_FP_MUL(a, b) \
    (((a) * (b)) >> RA_FP_SHIFT)

/* Divide two fixed point numbers. */
#define RA_FP_DIV(a, b) \
    (b == 0 ? (uint64_t)-1 : (((a) << RA_FP_SHIFT) / (b)))

#ifdef RA_DEBUG
#define DPRINTF(x)    do { if (ra_debug > 0) printf x; } while (0)
#define DPRINTFN(n, x)    do { if (ra_debug >= (n)) printf x; } while (0)
int ra_debug = 0;
#else
#define DPRINTF(x)    do { ; } while (0)
#define DPRINTFN(n, x)    do { ; } while (0)
#endif

#ifdef RA_DEBUG
void
ra_fixedp_split(uint32_t *i, uint32_t *f, uint64_t fp)
{
    uint64_t tmp;

    /* integer part */
    *i = (fp >> RA_FP_SHIFT);

     /* fractional part */
    tmp = (fp & ((uint64_t)-1 >> (64 - RA_FP_SHIFT)));
    tmp *= 100;
    *f = (uint32_t)(tmp >> RA_FP_SHIFT);
}

char *
ra_fp_sprintf(uint64_t fp)
{
    uint32_t i, f;
    static char buf[64];
    int ret;

    ra_fixedp_split(&i, &f, fp);
    ret = snprintf(buf, sizeof(buf), "%u.%02u", i, f);
    if (ret == -1 || ret >= sizeof(buf))
        return "ERR";

    return buf;
}
#endif /* RA_DEBUG */

static int is_ht(struct ieee80211_node *ni)
{
    return (ni->ni_flags & IEEE80211_NODE_HT);
}

static int is_vht(struct ieee80211_node *ni)
{
    return (ni->ni_flags & IEEE80211_NODE_VHT);
}

static int is_he(struct ieee80211_node *ni)
{
    return (ni->ni_flags & IEEE80211_NODE_HE);
}

static int support_nss(struct ieee80211_node *ni)
{
    uint32_t ntxstreams = 0;
    struct ieee80211com *ic = ni->ni_ic;
    int i;
    if ((ic->ic_tx_mcs_set & IEEE80211_TX_RX_MCS_NOT_EQUAL) == 0) {
        for (i = 0; i < 4; i++) {
            if ((is_vht(ni) || is_he(ni)) &&
                ic->ic_vht_sup_mcs[i] == 0) {
                break;
            } else if (ic->ic_sup_mcs[i] == 0) {
                break;
            }
            ntxstreams++;
            if (ntxstreams >= ni->ni_rx_nss)
                break;
        }
        return ntxstreams;
    }
    return MIN(1 + ((ic->ic_tx_mcs_set & IEEE80211_TX_SPATIAL_STREAMS) >> 2), ni->ni_rx_nss);
}

static void build_rateset(struct ieee80211_ra_node *rn, enum ieee80211_phymode mode)
{
    int i;
    struct ieee80211_ra_rate *ra_rate;
    const struct ieee80211_ht_rateset *ht_rate;
    const struct ieee80211_vht_rateset *vht_rate;
    const struct ieee80211_he_rateset *he_rate;
    rn->rs_phymode = mode;
    switch (rn->rs_phymode) {
        case IEEE80211_MODE_11N:
            rn->active_rs_count = IEEE80211_HT_NUM_RATESETS;
            for (i = 0; i < IEEE80211_HT_NUM_RATESETS; i++) {
                ra_rate = &rn->active_rs[i];
                ht_rate = &ieee80211_std_ratesets_11n[i];
                ra_rate->band_width = (i >= IEEE80211_HT_RATESET_CBW40_SISO ? IEEE80211_CHAN_WIDTH_40 : IEEE80211_CHAN_WIDTH_20);
                ra_rate->max_mcs = ht_rate->max_mcs;
                ra_rate->min_mcs = ht_rate->min_mcs;
                ra_rate->nrates = ht_rate->nrates;
                ra_rate->sgi = ht_rate->sgi;
                ra_rate->nss = (ht_rate->max_mcs + 1) / 8;
                ra_rate->rs_index = i;
                memcpy(ra_rate->rates, ht_rate->rates, sizeof(ht_rate->rates));
            }
            break;
            
        case IEEE80211_MODE_11AC:
            rn->active_rs_count = IEEE80211_VHT_NUM_RATESETS;
            for (i = 0; i < IEEE80211_HT_NUM_RATESETS; i++) {
                ra_rate = &rn->active_rs[i];
                vht_rate = &ieee80211_std_ratesets_11ac[i];
                int bw = IEEE80211_CHAN_WIDTH_20;
                switch (i / 4) {
                    case 0:
                        bw = IEEE80211_CHAN_WIDTH_20;
                        break;
                    case 1:
                        bw = IEEE80211_CHAN_WIDTH_40;
                        break;
                    case 2:
                        bw = IEEE80211_CHAN_WIDTH_80;
                        break;
                    case 3:
                        bw = IEEE80211_CHAN_WIDTH_160;
                        break;
                    default:
                        break;
                }
                ra_rate->band_width = bw;
                ra_rate->max_mcs = vht_rate->nrates - 1;
                ra_rate->min_mcs = 0;
                ra_rate->nrates = vht_rate->nrates;
                ra_rate->sgi = vht_rate->sgi;
                ra_rate->nss = vht_rate->num_ss;
                ra_rate->rs_index = i;
                memcpy(ra_rate->rates, vht_rate->rates, sizeof(vht_rate->rates));
            }
            break;
        
        case IEEE80211_MODE_11AX:
            rn->active_rs_count = IEEE80211_HT_NUM_RATESETS;
            for (i = 0; i < IEEE80211_HT_NUM_RATESETS; i++) {
                ra_rate = &rn->active_rs[i];
                he_rate = &ieee80211_std_ratesets_11ax[i];
                int bw = IEEE80211_CHAN_WIDTH_20;
                switch (i / 2) {
                    case 0:
                        bw = IEEE80211_CHAN_WIDTH_20;
                        break;
                    case 1:
                        bw = IEEE80211_CHAN_WIDTH_40;
                        break;
                    case 2:
                        bw = IEEE80211_CHAN_WIDTH_80;
                        break;
                    case 3:
                        bw = IEEE80211_CHAN_WIDTH_160;
                        break;
                    default:
                        break;
                }
                ra_rate->band_width = bw;
                ra_rate->max_mcs = he_rate->nrates - 1;
                ra_rate->min_mcs = 0;
                ra_rate->sgi = 0;
                ra_rate->nss = ((i + 1) % 2) + 1;
                ra_rate->nrates = he_rate->nrates;
                ra_rate->rs_index = i;
                memcpy(ra_rate->rates, he_rate->rates, sizeof(he_rate->rates));
            }
            break;
        default:
            XYLog("%s invalid mode=%d\n", __FUNCTION__, mode);
            break;
    }
}

const struct ieee80211_ra_rate *
ieee80211_ra_get_rateset(struct ieee80211_ra_node *ra, struct ieee80211com *ic, struct ieee80211_node *ni, int mcs)
{
    int i;
    int sup_nss = support_nss(ni);
    struct ieee80211_ra_rate *last_ra_rate = &ra->active_rs[ra->rs_index];
    if (last_ra_rate->min_mcs <= mcs && mcs <= last_ra_rate->max_mcs) {
        return last_ra_rate;
    }
    int search_direction = mcs - last_ra_rate->max_mcs;
    for (i = ra->rs_index; (search_direction > 0 ? (i <= ra->active_rs_count - 1) : (i >= 0)); search_direction > 0 ? i++ : i--) {
        const struct ieee80211_ra_rate *ra_rate = &ra->active_rs[i];
        if (ra_rate->sgi && !ieee80211_node_supports_sgi(ni))
            continue;
        if (ra_rate->nss > sup_nss)
            continue;
        if (ra_rate->band_width > ni->ni_chw)
            continue;
        if (mcs >= ra_rate->min_mcs && mcs <= ra_rate->max_mcs)
            return ra_rate;
    }
    panic("%s mcs=%d rs_count=%d sgi=%d nss=%d bw=%d rate==NULL!!!!\n", __FUNCTION__, mcs, ra->active_rs_count, ra->sgi, ra->nss, ra->bw);
}

int
ieee80211_ra_use_ht_sgi(struct ieee80211_node *ni)
{
    if ((ni->ni_chw == IEEE80211_CHAN_WIDTH_40) &&
        ieee80211_node_supports_ht_chan40(ni)) {
        if (ni->ni_flags & IEEE80211_NODE_HT_SGI40)
            return 1;
    } else if (ni->ni_flags & IEEE80211_NODE_HT_SGI20)
        return 1;
    
    return 0;
}

/*
 * Update goodput statistics.
 */

uint64_t
ieee80211_ra_get_txrate(struct ieee80211_ra_node *ra, struct ieee80211com *ic, struct ieee80211_node *ni, int mcs)
{
    const struct ieee80211_ra_rate *rs;
    uint64_t txrate;

    rs = ieee80211_ra_get_rateset(ra, ic, ni, mcs);
    txrate = rs->rates[mcs - rs->min_mcs];
    txrate <<= RA_FP_SHIFT; /* convert to fixed-point */
    txrate *= 500; /* convert to kbit/s */
    txrate /= 1000; /* convert to mbit/s */

    return txrate;
}

/*
 * Rate selection.
 */

/* A rate's goodput has to be at least this much larger to be "better". */
#define IEEE80211_RA_RATE_THRESHOLD    (RA_FP_1 / 64) /* ~ 0.015 */

int
ieee80211_ra_next_lower_intra_rate(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    const struct ieee80211_ra_rate *rs;
    int i, next;

    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    if (ni->ni_txmcs == rs->min_mcs)
        return rs->min_mcs;

    next = ni->ni_txmcs;
    for (i = rs->nrates - 1; i >= 0; i--) {
        if ((rn->valid_rates & (1 << (i + rs->min_mcs))) == 0)
            continue;
        if (i + rs->min_mcs < ni->ni_txmcs) {
            next = i + rs->min_mcs;
            break;
        }
    }

    return next;
}

int
ieee80211_ra_next_intra_rate(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    const struct ieee80211_ra_rate *rs;
    int i, next;

    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    if (ni->ni_txmcs == rs->max_mcs)
        return rs->max_mcs;

    next = ni->ni_txmcs;
    for (i = 0; i < rs->nrates; i++) {
        if ((rn->valid_rates & (1 << (i + rs->min_mcs))) == 0)
            continue;
        if (i + rs->min_mcs > ni->ni_txmcs) {
            next = i + rs->min_mcs;
            break;
        }
    }

    return next;
}

const struct ieee80211_ra_rate *
ieee80211_ra_next_rateset(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    const struct ieee80211_ra_rate *rs, *rsnext = NULL;
    int next = 0;
    bool found = false;

    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    if (rn->probing & IEEE80211_RA_PROBING_UP) {
        next = rs->rs_index;
        while (next < rn->active_rs_count - 1) {
            next++;
            rsnext = &rn->active_rs[next];
            if (rsnext->band_width > ni->ni_chw)
                continue;
            if (rsnext->nss > support_nss(ni))
                continue;
            found = true;
            break;
        }
        
    } else if (rn->probing & IEEE80211_RA_PROBING_DOWN) {
        next = rs->rs_index;
        while (next > 0) {
            next--;
            rsnext = &rn->active_rs[next];
            if (rsnext->band_width > ni->ni_chw)
                continue;
            if (rsnext->nss > support_nss(ni))
                continue;
            found = true;
            break;
        }
    } else
        panic("%s: invalid probing mode %d", __func__, rn->probing);
    
    if (found) {
#ifdef RA_DEBUG
        DPRINTF(("%s rs befor_idx=%d after_idx=%d sgi=%d nss=%d sup_nss=%d bw=%d probing=%d\n", __FUNCTION__, rs->rs_index, rsnext->rs_index, rsnext->sgi, rsnext->nss, support_nss(ni), rsnext->band_width, rn->probing));
#endif
        return rsnext;
    }
    return NULL;

//    if ((rsnext->mcs_mask & rn->valid_rates) == 0)
//        return NULL;
}

int
ieee80211_ra_best_mcs_in_rateset(struct ieee80211_ra_node *rn,
    const struct ieee80211_ra_rate *rs)
{
    uint64_t gmax = 0;
    int i, best_mcs = rs->min_mcs;

    for (i = 0; i < rs->nrates; i++) {
        int mcs = rs->min_mcs + i;
        struct ieee80211_ra_goodput_stats *g = &rn->g[mcs];
        if (((1 << mcs) & rn->valid_rates) == 0)
            continue;
        if (g->measured > gmax + IEEE80211_RA_RATE_THRESHOLD) {
            gmax = g->measured;
            best_mcs = mcs;
        }
    }

    return best_mcs;
}

void
ieee80211_ra_probe_next_rateset(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni, const struct ieee80211_ra_rate *rsnext)
{
    const struct ieee80211_ra_rate *rs;
    struct ieee80211_ra_goodput_stats *g;
    int best_mcs, i;

    /* Find most recently measured best MCS from the current rateset. */
    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    best_mcs = ieee80211_ra_best_mcs_in_rateset(rn, rs);

    /* Switch to the next rateset. */
    ni->ni_txmcs = rsnext->min_mcs;
    rn->bw = rsnext->band_width;
    rn->nss = rsnext->nss;
    rn->sgi = rsnext->sgi;
    rn->rs_index = rsnext->rs_index;
    if ((rn->valid_rates & (1 << rsnext->min_mcs)) == 0)
        ni->ni_txmcs = ieee80211_ra_next_intra_rate(rn, ic, ni);

    /* Select the lowest rate from the next rateset with loss-free
     * goodput close to the current best measurement. */
    g = &rn->g[best_mcs];
    for (i = 0; i < rsnext->nrates; i++) {
        int mcs = rsnext->min_mcs + i;
        uint64_t txrate = rsnext->rates[i];

        if ((rn->valid_rates & (1 << mcs)) == 0)
            continue;

        txrate = txrate * 500; /* convert to kbit/s */
        txrate <<= RA_FP_SHIFT; /* convert to fixed-point */
        txrate /= 1000; /* convert to mbit/s */

        if (txrate > g->measured + IEEE80211_RA_RATE_THRESHOLD) {
            ni->ni_txmcs = mcs;
            break;
        }
    }
    /* If all rates are lower the maximum rate is the closest match. */
    if (i == rsnext->nrates)
        ni->ni_txmcs = rsnext->max_mcs;

    /* Add rates from the next rateset as candidates. */
    rn->candidate_rates |= (1 << ni->ni_txmcs);
    if (rn->probing & IEEE80211_RA_PROBING_UP) {
        rn->candidate_rates |=
          (1 << ieee80211_ra_next_intra_rate(rn, ic, ni));
    } else if (rn->probing & IEEE80211_RA_PROBING_DOWN) {
        rn->candidate_rates |=
            (1 << ieee80211_ra_next_lower_intra_rate(rn, ic, ni));
    } else
        panic("%s: invalid probing mode %d", __func__, rn->probing);
}

int
ieee80211_ra_next_mcs(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    int next;

    if (rn->probing & IEEE80211_RA_PROBING_DOWN)
        next = ieee80211_ra_next_lower_intra_rate(rn, ic, ni);
    else if (rn->probing & IEEE80211_RA_PROBING_UP)
        next = ieee80211_ra_next_intra_rate(rn, ic, ni);
    else
        panic("%s: invalid probing mode %d", __func__, rn->probing);

    return next;
}

void
ieee80211_ra_probe_clear(struct ieee80211_ra_node *rn,
    struct ieee80211_node *ni)
{
    struct ieee80211_ra_goodput_stats *g = &rn->g[ni->ni_txmcs];

    g->nprobe_pkts = 0;
    g->nprobe_fail = 0;
}

int
ieee80211_ra_probe_valid(struct ieee80211_ra_goodput_stats *g)
{
    /* 128 packets make up a valid probe in any case. */
    if (g->nprobe_pkts >= 128)
        return 1;
    
    /* 8 packets with > 75% loss make a valid probe, too. */
    if (g->nprobe_pkts >= 8 &&
        g->nprobe_pkts - g->nprobe_fail < g->nprobe_pkts / 4)
        return 1;
    
    return 0;
}

void
ieee80211_ra_probe_done(struct ieee80211_ra_node *rn)
{
    rn->probing = IEEE80211_RA_NOT_PROBING;
    rn->probed_rates = 0;
    rn->valid_probes = 0;
    rn->candidate_rates = 0;
}

int
ieee80211_ra_intra_mode_ra_finished(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    const struct ieee80211_ra_rate *rs;
    struct ieee80211_ra_goodput_stats *g = &rn->g[ni->ni_txmcs];
    int next_mcs, best_mcs;
    uint64_t next_rate;

    rn->probed_rates = (rn->probed_rates | (1 << ni->ni_txmcs));

    /* Check if the min/max MCS in this rateset has been probed. */
    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    if (rn->probing & IEEE80211_RA_PROBING_DOWN) {
        if (ni->ni_txmcs == rs->min_mcs ||
            rn->probed_rates & (1 << rs->min_mcs)) {
            ieee80211_ra_trigger_next_rateset(rn, ic, ni);
            return 1;
        }
    } else if (rn->probing & IEEE80211_RA_PROBING_UP) {
        if (ni->ni_txmcs == rs->max_mcs ||
            rn->probed_rates & (1 << rs->max_mcs)) {
            ieee80211_ra_trigger_next_rateset(rn, ic, ni);
            return 1;
        }
    }

    /*
     * Check if the measured goodput is loss-free and better than the
     * loss-free goodput of the candidate rate.
     */
    next_mcs = ieee80211_ra_next_mcs(rn, ic, ni);
    if (next_mcs == ni->ni_txmcs) {
        ieee80211_ra_trigger_next_rateset(rn, ic, ni);
        return 1;
    }
    next_rate = ieee80211_ra_get_txrate(rn, ic, ni, next_mcs);
    if (g->loss == 0 &&
        g->measured >= next_rate + IEEE80211_RA_RATE_THRESHOLD) {
        ieee80211_ra_trigger_next_rateset(rn, ic, ni);
        return 1;
    }

    /* Check if we had a better measurement at a previously probed MCS. */
    best_mcs = ieee80211_ra_best_mcs_in_rateset(rn, rs);
    if (best_mcs != ni->ni_txmcs && (rn->probed_rates & (1 << best_mcs))) {
        if ((rn->probing & IEEE80211_RA_PROBING_UP) &&
            best_mcs < ni->ni_txmcs) {
            ieee80211_ra_trigger_next_rateset(rn, ic, ni);
            return 1;
        }
        if ((rn->probing & IEEE80211_RA_PROBING_DOWN) &&
            best_mcs > ni->ni_txmcs) {
            ieee80211_ra_trigger_next_rateset(rn, ic, ni);
            return 1;
        }
    }

    /* Check if all rates in the set of candidate rates have been probed. */
    if ((rn->candidate_rates & rn->probed_rates) == rn->candidate_rates) {
        /* Remain in the current rateset until above checks trigger. */
        rn->probing &= ~IEEE80211_RA_PROBING_INTER;
        return 1;
    }

    return 0;
}

void
ieee80211_ra_trigger_next_rateset(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    const struct ieee80211_ra_rate *rsnext;

    rsnext = ieee80211_ra_next_rateset(rn, ic, ni);
    if (rsnext) {
        ieee80211_ra_probe_next_rateset(rn, ic, ni, rsnext);
        rn->probing |= IEEE80211_RA_PROBING_INTER;
    } else
        rn->probing &= ~IEEE80211_RA_PROBING_INTER;
}

int
ieee80211_ra_inter_mode_ra_finished(struct ieee80211_ra_node *rn,
    struct ieee80211_node *ni)
{
    return ((rn->probing & IEEE80211_RA_PROBING_INTER) == 0);
}

int
ieee80211_ra_best_rate(struct ieee80211_ra_node *rn,
    struct ieee80211_node *ni)
{
    int i, best = rn->best_mcs;
    uint64_t gmax = rn->g[rn->best_mcs].measured;

    for (i = 0; i < nitems(rn->g); i++) {
        struct ieee80211_ra_goodput_stats *g = &rn->g[i];
        if (((1 << i) & rn->valid_rates) == 0)
            continue;
        if (g->measured > gmax + IEEE80211_RA_RATE_THRESHOLD) {
            gmax = g->measured;
            best = i;
        }
    }

#ifdef RA_DEBUG
    if (rn->best_mcs != best) {
        DPRINTF(("MCS %d is best; MCS{cur|avg|loss}:", best));
        for (i = 0; i < IEEE80211_HT_RATESET_NUM_MCS; i++) {
            struct ieee80211_ra_goodput_stats *g = &rn->g[i];
            if ((rn->valid_rates & (1 << i)) == 0)
                continue;
            DPRINTF((" %d{%s|", i, ra_fp_sprintf(g->measured)));
            DPRINTF(("%s|", ra_fp_sprintf(g->average)));
            DPRINTF(("%s%%}", ra_fp_sprintf(g->loss)));
        }
        DPRINTF(("\n"));
    }
#endif
    return best;
}

void
ieee80211_ra_probe_next_rate(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    /* Select the next rate to probe. */
    rn->probed_rates |= (1 << ni->ni_txmcs);
    ni->ni_txmcs = ieee80211_ra_next_mcs(rn, ic, ni);
}

int
ieee80211_ra_valid_tx_mcs(struct ieee80211_node *ni, int mcs)
{
    struct ieee80211com *ic = ni->ni_ic;
    uint32_t ntxstreams = support_nss(ni);
    static const int max_ht_mcs[] = { 7, 15, 23, 31 };
    static const int max_vht_mcs = 9;

    if ((ic->ic_tx_mcs_set & IEEE80211_TX_RX_MCS_NOT_EQUAL) == 0) {
        if (is_he(ni) || is_vht(ni))
            return isset(ic->ic_vht_sup_mcs, mcs);
        return isset(ic->ic_sup_mcs, mcs);
    }

    if (is_he(ni) || is_vht(ni))
        return mcs < max_vht_mcs && isset(ic->ic_vht_sup_mcs, mcs);

    if (ntxstreams < 1 || ntxstreams > 4)
        panic("invalid number of Tx streams: %u", ntxstreams);
    return (mcs <= max_ht_mcs[ntxstreams - 1] && isset(ic->ic_sup_mcs, mcs));
}

int
ieee80211_ra_vht_highest_rx_mcs(struct ieee80211_node *ni, int nss)
{
    uint16_t rx_mcs;

    rx_mcs = le16toh(ni->ni_vht_mcsinfo.rx_mcs_map) &
        (IEEE80211_VHT_MCS_NOT_SUPPORTED << (2 * (nss - 1)));
    rx_mcs >>= (2 * (nss - 1));

    return rx_mcs;
}

int
ieee80211_ra_valid_rx_mcs(struct ieee80211_node *ni, int mcs)
{
    uint16_t rx_mcs;

    if (is_he(ni) || is_vht(ni)) {
        rx_mcs = ieee80211_ra_vht_highest_rx_mcs(ni, ni->ni_rx_nss > 1 ? 2 : 1);
        if (rx_mcs == 0 && mcs == 8)
            return 0;
        else if (rx_mcs == 1 && mcs == 9)
            return 0;

        if (mcs == 9 && ni->ni_chw == IEEE80211_CHAN_WIDTH_20)
            return 0;
    } else if (!isset(ni->ni_rxmcs, mcs))
        return 0;
    return 1;
}

uint32_t
ieee80211_ra_valid_rates(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    uint32_t valid_mcs = 0;
    uint32_t max_mcs = (is_he(ni) || is_vht(ni)) ? IEEE80211_VHT_RATESET_NUM_MCS : IEEE80211_HT_RATESET_NUM_MCS;
    int i;

    for (i = 0; i < max_mcs; i++) {
        if (!ieee80211_ra_valid_rx_mcs(ni, i))
            continue;

        if (!ieee80211_ra_valid_tx_mcs(ni, i))
            continue;
        valid_mcs |= (1 << i);
    }

    return valid_mcs;
}

void
ieee80211_ra_add_stats_ht(struct ieee80211_ra_node *rn,
    struct ieee80211com *ic, struct ieee80211_node *ni,
    int mcs, uint32_t total, uint32_t fail)
{
    static const uint64_t alpha = RA_FP_1 / 8; /* 1/8 = 0.125 */
    static const uint64_t beta =  RA_FP_1 / 4; /* 1/4 = 0.25 */
    int s;
    struct ieee80211_ra_goodput_stats *g;
    uint64_t sfer, rate, delta;

    /*
     * Ignore invalid values. These values may come from hardware
     * so asserting valid values via panic is not appropriate.
     */
    if (mcs < 0 || mcs >= IEEE80211_HT_RATESET_NUM_MCS)
        return;
    if (total == 0)
        return;

    s = splnet();

    g = &rn->g[mcs];
    g->nprobe_pkts += total;
    g->nprobe_fail += fail;

    if (!ieee80211_ra_probe_valid(g)) {
        splx(s);
        return;
    }
    rn->valid_probes |= 1U << mcs;

    if (g->nprobe_fail > g->nprobe_pkts) {
        DPRINTF(("%s fail %u > pkts %u\n",
            ether_sprintf(ni->ni_macaddr),
            g->nprobe_fail, g->nprobe_pkts));
        g->nprobe_fail = g->nprobe_pkts;
    }

    sfer = g->nprobe_fail << RA_FP_SHIFT;
    sfer /= g->nprobe_pkts;
    g->nprobe_fail = 0;
    g->nprobe_pkts = 0;

    rate = ieee80211_ra_get_txrate(rn, ic, ni, mcs);

    g->loss = sfer * 100;
    g->measured = RA_FP_MUL(RA_FP_1 - sfer, rate);
    g->average = RA_FP_MUL(RA_FP_1 - alpha, g->average);
    g->average += RA_FP_MUL(alpha, g->measured);

    g->stddeviation = RA_FP_MUL(RA_FP_1 - beta, g->stddeviation);
    if (g->average > g->measured)
        delta = g->average - g->measured;
    else
        delta = g->measured - g->average;
    g->stddeviation += RA_FP_MUL(beta, delta);

    splx(s);
}

void
ieee80211_ra_choose(struct ieee80211_ra_node *rn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
    struct ieee80211_ra_goodput_stats *g = &rn->g[ni->ni_txmcs];
    int s;
    const struct ieee80211_ra_rate *rs, *rsnext;

    s = splnet();

    if (rn->valid_rates == 0)
        rn->valid_rates = ieee80211_ra_valid_rates(ic, ni);

    if (rn->probing) {
        /* Probe another rate or settle at the best rate. */
        if (!(rn->valid_probes & (1UL << ni->ni_txmcs))) {
            splx(s);
            return;
        }
        ieee80211_ra_probe_clear(rn, ni);
        if (!ieee80211_ra_intra_mode_ra_finished(rn, ic, ni)) {
            ieee80211_ra_probe_next_rate(rn, ic, ni);
            DPRINTFN(3, ("probing MCS %d\n", ni->ni_txmcs));
        } else if (ieee80211_ra_inter_mode_ra_finished(rn, ni)) {
            rn->best_mcs = ieee80211_ra_best_rate(rn, ni);
            ni->ni_txmcs = rn->best_mcs;
            ieee80211_ra_probe_done(rn);
        }

        splx(s);
        return;
    } else {
        rn->valid_probes = 0;
    }

    rs = ieee80211_ra_get_rateset(rn, ic, ni, ni->ni_txmcs);
    if ((g->measured >> RA_FP_SHIFT) == 0LL ||
        (g->average >= 3 * g->stddeviation &&
        g->measured < g->average - 3 * g->stddeviation)) {
        /* Channel becomes bad. Probe downwards. */
        rn->probing = IEEE80211_RA_PROBING_DOWN;
        rn->probed_rates = 0;
        if (ni->ni_txmcs == rs->min_mcs) {
            rsnext = ieee80211_ra_next_rateset(rn, ic, ni);
            if (rsnext) {
                ieee80211_ra_probe_next_rateset(rn, ic, ni,
                    rsnext);
            } else {
                /* Cannot probe further down. */
                rn->probing = IEEE80211_RA_NOT_PROBING;
            }
        } else {
            ni->ni_txmcs = ieee80211_ra_next_mcs(rn, ic, ni);
            rn->candidate_rates = (1 << ni->ni_txmcs);
        }
    } else if (g->loss < 2 * RA_FP_1 ||
        g->measured > g->average + 3 * g->stddeviation) {
        /* Channel becomes good. */
        rn->probing = IEEE80211_RA_PROBING_UP;
        rn->probed_rates = 0;
        if (ni->ni_txmcs == rs->max_mcs) {
            rsnext = ieee80211_ra_next_rateset(rn, ic, ni);
            if (rsnext) {
                ieee80211_ra_probe_next_rateset(rn, ic, ni,
                    rsnext);
            } else {
                /* Cannot probe further up. */
                rn->probing = IEEE80211_RA_NOT_PROBING;
            }
        } else {
            ni->ni_txmcs = ieee80211_ra_next_mcs(rn, ic, ni);
            rn->candidate_rates = (1 << ni->ni_txmcs);
        }
    } else {
        /* Remain at current rate. */
        rn->probing = IEEE80211_RA_NOT_PROBING;
        rn->probed_rates = 0;
        rn->candidate_rates = 0;
    }

    splx(s);

    if (rn->probing) {
        if (rn->probing & IEEE80211_RA_PROBING_UP)
            DPRINTFN(2, ("channel becomes good; probe up\n"));
        else
            DPRINTFN(2, ("channel becomes bad; probe down\n"));

        DPRINTFN(3, ("measured: %s Mbit/s\n",
            ra_fp_sprintf(g->measured)));
        DPRINTFN(3, ("average: %s Mbit/s\n",
            ra_fp_sprintf(g->average)));
        DPRINTFN(3, ("stddeviation: %s\n",
            ra_fp_sprintf(g->stddeviation)));
        DPRINTFN(3, ("loss: %s%%\n", ra_fp_sprintf(g->loss)));
    }
}

void
ieee80211_ra_node_init(struct ieee80211com *ic, struct ieee80211_ra_node *rn, struct ieee80211_node *ni)
{
    memset(rn, 0, sizeof(*rn));
    build_rateset(rn, (enum ieee80211_phymode)ic->ic_curmode);
    rn->bw = ni->ni_chw;
    rn->sgi = ieee80211_node_supports_sgi(ni);
    rn->nss = support_nss(ni);
    switch (ni->ni_chw) {
        case IEEE80211_CHAN_WIDTH_20:
            if (is_he(ni)) {
                rn->rs_index = IEEE80211_HE_RATESET_SISO;
            } else if (is_vht(ni)) {
                rn->rs_index = IEEE80211_VHT_RATESET_SISO;
            } else if (is_ht(ni)) {
                rn->rs_index = IEEE80211_HT_RATESET_SISO;
            }
            break;
        case IEEE80211_CHAN_WIDTH_40:
            if (is_he(ni)) {
                rn->rs_index = IEEE80211_HE_RATESET_SISO_40;
            } else if (is_vht(ni)) {
                rn->rs_index = IEEE80211_VHT_RATESET_SISO_40;
            } else if (is_ht(ni)) {
                rn->rs_index = IEEE80211_HT_RATESET_CBW40_SISO;
            }
            break;
        case IEEE80211_CHAN_WIDTH_80:
            if (is_he(ni)) {
                rn->rs_index = IEEE80211_HE_RATESET_SISO_80;
            } else if (is_vht(ni)) {
                rn->rs_index = IEEE80211_VHT_RATESET_SISO_80;
            }
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            if (is_he(ni)) {
                rn->rs_index = IEEE80211_HE_RATESET_SISO_160;
            } else if (is_vht(ni)) {
                rn->rs_index = IEEE80211_VHT_RATESET_SISO_160;
            }
            break;
            
        default:
            rn->rs_index = 0;
            break;
    }
}
