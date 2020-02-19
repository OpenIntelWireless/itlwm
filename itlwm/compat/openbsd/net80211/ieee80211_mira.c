/*	$OpenBSD: ieee80211_mira.c,v 1.16 2019/07/29 10:50:09 stsp Exp $	*/

/*
 * Copyright (c) 2016 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2016 Theo Buehler <tb@openbsd.org>
 * Copyright (c) 2006 Damien Bergamini <damien.bergamini@free.fr>
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
#include <sys/_arc4random.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_mira.h>

/* Allow for aggressive down probing when channel quality changes. */
#define MIRA_AGGRESSIVE_DOWNWARDS_PROBING

const struct ieee80211_ht_rateset *	ieee80211_mira_get_rateset(int, int);
void	ieee80211_mira_probe_timeout_up(void *);
void	ieee80211_mira_probe_timeout_down(void *);
uint64_t ieee80211_mira_get_txrate(int, int);
uint16_t ieee80211_mira_legacy_txtime(uint32_t, int, struct ieee80211com *);
uint32_t ieee80211_mira_ht_txtime(uint32_t, int, int, int);
int	ieee80211_mira_best_basic_rate(struct ieee80211_node *);
int	ieee80211_mira_ack_rate(struct ieee80211_node *);
uint64_t ieee80211_mira_toverhead(struct ieee80211_mira_node *,
	    struct ieee80211com *, struct ieee80211_node *);
void	ieee80211_mira_update_stats(struct ieee80211_mira_node *,
	    struct ieee80211com *, struct ieee80211_node *);
void	ieee80211_mira_reset_goodput_stats(struct ieee80211_mira_node *);
void	ieee80211_mira_reset_driver_stats(struct ieee80211_mira_node *);
int	ieee80211_mira_next_lower_intra_rate(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
int	ieee80211_mira_next_intra_rate(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
const struct ieee80211_ht_rateset * ieee80211_mira_next_rateset(
		    struct ieee80211_mira_node *, struct ieee80211_node *);
int	ieee80211_mira_best_mcs_in_rateset(struct ieee80211_mira_node *,
	    const struct ieee80211_ht_rateset *);
void	ieee80211_mira_probe_next_rateset(struct ieee80211_mira_node *,
	    struct ieee80211_node *, const struct ieee80211_ht_rateset *);
int	ieee80211_mira_next_mcs(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
int	ieee80211_mira_prev_mcs(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
int	ieee80211_mira_probe_valid(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
void	ieee80211_mira_probe_done(struct ieee80211_mira_node *);
int	ieee80211_mira_intra_mode_ra_finished(
	    struct ieee80211_mira_node *, struct ieee80211_node *);
void	ieee80211_mira_trigger_next_rateset(struct ieee80211_mira_node *mn,
	    struct ieee80211_node *);
int	ieee80211_mira_inter_mode_ra_finished(
	    struct ieee80211_mira_node *, struct ieee80211_node *);
int	ieee80211_mira_best_rate(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
void	ieee80211_mira_update_probe_interval(struct ieee80211_mira_node *,
	    struct ieee80211_mira_goodput_stats *);
void	ieee80211_mira_schedule_probe_timers(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
int	ieee80211_mira_check_probe_timers(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
void	ieee80211_mira_probe_next_rate(struct ieee80211_mira_node *,
	    struct ieee80211_node *);
int	ieee80211_mira_valid_tx_mcs(struct ieee80211com *, int);
uint32_t ieee80211_mira_valid_rates(struct ieee80211com *,
	    struct ieee80211_node *);
uint32_t ieee80211_mira_mcs_below(struct ieee80211_mira_node *, int, int);
void	ieee80211_mira_set_rts_threshold(struct ieee80211_mira_node *,
	    struct ieee80211com *, struct ieee80211_node *);
void	ieee80211_mira_reset_collision_stats(struct ieee80211_mira_node *);

/* We use fixed point arithmetic with 64 bit integers. */
#define MIRA_FP_SHIFT	21
#define MIRA_FP_INT(x)	(x ## ULL << MIRA_FP_SHIFT) /* the integer x */
#define MIRA_FP_1	MIRA_FP_INT(1)

/* Multiply two fixed point numbers. */
#define MIRA_FP_MUL(a, b) \
	(((a) * (b)) >> MIRA_FP_SHIFT)

/* Divide two fixed point numbers. */
#define MIRA_FP_DIV(a, b) \
	(b == 0 ? (uint64_t)-1 : (((a) << MIRA_FP_SHIFT) / (b)))

#ifdef MIRA_DEBUG
#define DPRINTF(x)	do { if (mira_debug > 0) printf x; } while (0)
#define DPRINTFN(n, x)	do { if (mira_debug >= (n)) printf x; } while (0)
int mira_debug = 0;
#else
#define DPRINTF(x)	do { ; } while (0)
#define DPRINTFN(n, x)	do { ; } while (0)
#endif

#ifdef MIRA_DEBUG
void
mira_fixedp_split(uint32_t *i, uint32_t *f, uint64_t fp)
{
	uint64_t tmp;

	/* integer part */
	*i = (fp >> MIRA_FP_SHIFT);

 	/* fractional part */
	tmp = (fp & ((uint64_t)-1 >> (64 - MIRA_FP_SHIFT)));
	tmp *= 100;
	*f = (uint32_t)(tmp >> MIRA_FP_SHIFT);
}

char *
mira_fp_sprintf(uint64_t fp)
{
	uint32_t i, f;
	static char buf[64];
	int ret;

	mira_fixedp_split(&i, &f, fp);
	ret = snprintf(buf, sizeof(buf), "%u.%02u", i, f);
	if (ret == -1 || ret >= sizeof(buf))
		return "ERR";

	return buf;
}

void
mira_print_driver_stats(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni) {
	DPRINTF(("%s driver stats:\n", ether_sprintf(ni->ni_macaddr)));
	DPRINTF(("mn->frames = %u\n", mn->frames));
	DPRINTF(("mn->retries = %u\n", mn->retries));
	DPRINTF(("mn->txfail = %u\n", mn->txfail));
	DPRINTF(("mn->ampdu_size = %u\n", mn->ampdu_size));
	DPRINTF(("mn->agglen = %u\n", mn->agglen));
}
#endif /* MIRA_DEBUG */

const struct ieee80211_ht_rateset *
ieee80211_mira_get_rateset(int mcs, int sgi)
{
	const struct ieee80211_ht_rateset *rs;
	int i;

	for (i = 0; i < IEEE80211_HT_NUM_RATESETS; i++) {
		rs = &ieee80211_std_ratesets_11n[i];
		if (sgi != rs->sgi)
			continue;
		if (mcs >= rs->min_mcs && mcs <= rs->max_mcs)
			return rs;
	}

	panic("MCS %d is not part of any rateset", mcs);
    return NULL;
}

/*
 * Probe timers.
 */

/* Constants related to timeouts for time-driven rate probing. */
#define IEEE80211_MIRA_PROBE_TIMEOUT_MIN	2		/* in msec */
#define IEEE80211_MIRA_PROBE_INTVAL_MAX		(1 << 10)	/* 2^10 */

void
ieee80211_mira_probe_timeout_up(void *arg)
{
	struct ieee80211_mira_node *mn = (struct ieee80211_mira_node *)arg;
	int s;

	s = splnet();
	mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_UP] = 1;
	DPRINTFN(3, ("probe up timeout fired\n"));
	splx(s);
}

void
ieee80211_mira_probe_timeout_down(void *arg)
{
	struct ieee80211_mira_node *mn = (struct ieee80211_mira_node *)arg;
	int s;

	s = splnet();
	mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_DOWN] = 1;
	DPRINTFN(3, ("probe down timeout fired\n"));
	splx(s);
}

/*
 * Update goodput statistics.
 */

uint64_t
ieee80211_mira_get_txrate(int mcs, int sgi)
{
	const struct ieee80211_ht_rateset *rs;
	uint64_t txrate;

	rs = ieee80211_mira_get_rateset(mcs, sgi);
	txrate = rs->rates[mcs - rs->min_mcs];
	txrate <<= MIRA_FP_SHIFT; /* convert to fixed-point */
	txrate *= 500; /* convert to kbit/s */
	txrate /= 1000; /* convert to mbit/s */

	return txrate;
}

/* Based on rt2661_txtime in the ral(4) driver. */
uint16_t
ieee80211_mira_legacy_txtime(uint32_t len, int rate, struct ieee80211com *ic)
{
#define MIRA_RATE_IS_OFDM(rate) ((rate) >= 12 && (rate) != 22)
	uint16_t txtime;

	if (MIRA_RATE_IS_OFDM(rate)) {
		/* IEEE Std 802.11g-2003, pp. 44 */
		txtime = (8 + 4 * len + 3 + rate - 1) / rate;
		txtime = 16 + 4 + 4 * txtime + 6;
	} else {
		/* IEEE Std 802.11b-1999, pp. 28 */
		txtime = (16 * len + rate - 1) / rate;
		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			txtime +=  72 + 24;
		else
			txtime += 144 + 48;
	}
	return txtime;
}

uint32_t
ieee80211_mira_ht_txtime(uint32_t len, int mcs, int is2ghz, int sgi)
{
	const struct ieee80211_ht_rateset *rs;
	/* XXX These constants should be macros in ieee80211.h instead. */
	const uint32_t t_lstf = 8; /* usec legacy short training field */
	const uint32_t t_lltf = 8; /* usec legacy long training field */
	const uint32_t t_lsig = 4; /* usec legacy signal field */
	const uint32_t t_htstf = 4; /* usec HT short training field */
	const uint32_t t_ltstf = 4; /* usec HT long training field */
	const uint32_t t_htsig = 8; /* usec HT signal field */
	const uint32_t t_sym = 4; /* usec symbol interval */
	const uint32_t t_syms = 3; /* usec symbol interval; XXX actually 3.6 */
	uint32_t n_sym, n_dbps;
	uint32_t t_plcp;
	uint32_t t_data;
	uint32_t txtime;

	/*
	 * Calculate approximate frame Tx time in usec.
	 * See 802.11-2012, 20.4.3 "TXTIME calculation" and
	 * 20.3.11.1 "Equation (20-32)".
	 * XXX Assumes a 20MHz channel, HT-mixed frame format, no STBC.
	 */
	t_plcp = t_lstf + t_lltf + t_lsig + t_htstf + 4 * t_ltstf + t_htsig;
	rs = ieee80211_mira_get_rateset(mcs, sgi);
	n_dbps = rs->rates[mcs - rs->min_mcs] * 2;
	n_sym = ((8 * len + 16 + 6) / n_dbps); /* "Equation (20-32)" */
	if (sgi)
		t_data = (t_syms * n_sym) / t_sym;
	else
		t_data = t_sym * n_sym;

	txtime = t_plcp + t_data;
	if (is2ghz)
		txtime += 6; /* aSignalExtension */

	return txtime;
}

int
ieee80211_mira_best_basic_rate(struct ieee80211_node *ni)
{
	struct ieee80211_rateset *rs = &ni->ni_rates;
	int i, best, rval;

	/* Default to 1 Mbit/s on 2GHz and 6 Mbit/s on 5GHz. */
	best = IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) ? 2 : 12;

	for (i = 0; i < rs->rs_nrates; i++) {
		if ((rs->rs_rates[i] & IEEE80211_RATE_BASIC) == 0)
			continue;
		rval = (rs->rs_rates[i] & IEEE80211_RATE_VAL);
		if (rval > best)
			best = rval;
	}

	return best;
}

/* 
 * See 802.11-2012, 9.7.6.5 "Rate selection for control response frames".
 * XXX Does not support BlockAck.
 */
int
ieee80211_mira_ack_rate(struct ieee80211_node *ni)
{
	/* 
	 * Assume the ACK was sent at a mandatory ERP OFDM rate.
	 * In the worst case, the driver has retried at non-HT rates,
	 * so for MCS 0 assume we didn't actually send an OFDM frame
	 * and ACKs arrived at a basic rate.
	 */
	if (ni->ni_txmcs == 0)
		return ieee80211_mira_best_basic_rate(ni);
	else if (ni->ni_txmcs == 1)
		return 12;	/* 6 Mbit/s */
	else if (ni->ni_txmcs >= 2)
		return 24;	/* 12 Mbit/s */
	else
		return 48;	/* 24 Mbit/s */
}

uint64_t
ieee80211_mira_toverhead(struct ieee80211_mira_node *mn,
    struct ieee80211com *ic, struct ieee80211_node *ni)
{
/* XXX These should be macros in ieee80211.h. */
#define MIRA_RTSLEN IEEE80211_MIN_LEN
#define MIRA_CTSLEN (sizeof(struct ieee80211_frame_cts) + IEEE80211_CRC_LEN)
	uint32_t overhead;
	uint64_t toverhead;
	int rate, rts;
	enum ieee80211_htprot htprot;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	overhead = ieee80211_mira_ht_txtime(0, ni->ni_txmcs,
	    IEEE80211_IS_CHAN_2GHZ(ni->ni_chan), sgi);

	htprot = (enum ieee80211_htprot)(ic->ic_bss->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
	if (htprot == IEEE80211_HTPROT_NONMEMBER ||
	    htprot == IEEE80211_HTPROT_NONHT_MIXED)
		rts = 1;
	else if (htprot == IEEE80211_HTPROT_20MHZ &&
		(ic->ic_htcaps & IEEE80211_HTCAP_CBW20_40))
		rts = 1;
	else
		rts = (mn->ampdu_size > ieee80211_mira_get_rts_threshold(mn,
		    ic, ni, mn->ampdu_size));

	if (rts) {
		/* Assume RTS/CTS were sent at a basic rate. */
		rate = ieee80211_min_basic_rate(ic);
		overhead += ieee80211_mira_legacy_txtime(MIRA_RTSLEN, rate, ic);
		overhead += ieee80211_mira_legacy_txtime(MIRA_CTSLEN, rate, ic);
	}

	/* XXX This does not yet support BlockAck. */
	rate = ieee80211_mira_ack_rate(ni);
	overhead += ieee80211_mira_legacy_txtime(IEEE80211_ACK_LEN, rate, ic);

	toverhead = overhead;
	toverhead <<= MIRA_FP_SHIFT; /* convert to fixed-point */
	toverhead /= 1000; /* convert to msec */
	toverhead /= 1000; /* convert to sec */

#ifdef MIRA_DEBUG
	if (mira_debug > 3) {
		uint32_t txtime;
		txtime = ieee80211_mira_ht_txtime(mn->ampdu_size, ni->ni_txmcs,
		    IEEE80211_IS_CHAN_2GHZ(ni->ni_chan), sgi);
		txtime += overhead - ieee80211_mira_ht_txtime(0, ni->ni_txmcs,
		    IEEE80211_IS_CHAN_2GHZ(ni->ni_chan), sgi);
		DPRINTFN(4, ("txtime: %u usec\n", txtime));
		DPRINTFN(4, ("overhead: %u usec\n", overhead));
		DPRINTFN(4, ("toverhead: %s\n", mira_fp_sprintf(toverhead)));
	}
#endif
	return toverhead;
}

void
ieee80211_mira_update_stats(struct ieee80211_mira_node *mn,
    struct ieee80211com *ic, struct ieee80211_node *ni)
{
	/* Magic numbers from MiRA paper. */
	static const uint64_t alpha = MIRA_FP_1 / 8; /* 1/8 = 0.125 */
	static const uint64_t beta =  MIRA_FP_1 / 4; /* 1/4 = 0.25 */
	uint64_t sfer, delta, toverhead;
	uint64_t agglen = mn->agglen;
	uint64_t ampdu_size = mn->ampdu_size * 8; /* convert to bits */
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;
	uint64_t rate = ieee80211_mira_get_txrate(ni->ni_txmcs, sgi);
	struct ieee80211_mira_goodput_stats *g = &mn->g[ni->ni_txmcs];

	g->nprobes += mn->agglen;
	g->nprobe_bytes += mn->ampdu_size;

	ampdu_size <<= MIRA_FP_SHIFT; /* convert to fixed-point */
	agglen <<= MIRA_FP_SHIFT;
	/* XXX range checks? */

	ampdu_size = ampdu_size / 1000; /* kbit */
	ampdu_size = ampdu_size / 1000; /* mbit */

	/* Compute Sub-Frame Error Rate (see section 2.2 in MiRA paper). */
	sfer = (mn->frames * mn->retries + mn->txfail);
	if ((sfer >> MIRA_FP_SHIFT) != 0) { /* bug in wifi driver */
		if (ic->ic_if.if_flags & IFF_DEBUG) {
#ifdef DIAGNOSTIC
			printf("%s: mira sfer overflow\n",
			    ether_sprintf(ni->ni_macaddr));
#endif
#ifdef MIRA_DEBUG
			mira_print_driver_stats(mn, ni);
#endif
		}
		ieee80211_mira_probe_done(mn);
		return;
	}
	sfer <<= MIRA_FP_SHIFT; /* convert to fixed-point */
	sfer /= ((mn->retries + 1) * mn->frames);
	if (sfer > MIRA_FP_1) { /* bug in wifi driver */
		if (ic->ic_if.if_flags & IFF_DEBUG) {
#ifdef DIAGNOSTIC
			printf("%s: mira sfer > 1\n",
			    ether_sprintf(ni->ni_macaddr));
#endif
#ifdef MIRA_DEBUG
			mira_print_driver_stats(mn, ni);
#endif
		}
		sfer = MIRA_FP_1; /* round down */
	}

	/* Store current loss percentage SFER. */
	g->loss = sfer * 100;
#ifdef MIRA_DEBUG
	if (g->loss && ieee80211_mira_probe_valid(mn, ni))
		DPRINTFN(2, ("frame error rate at MCS %d: %s%%\n",
		    ni->ni_txmcs, mira_fp_sprintf(g->loss)));
#endif

	/*
	 * Update goodput statistics (see section 5.1.2 in MiRA paper).
	 * We use a slightly modified but equivalent calculation which
	 * is tuned towards our fixed-point number format.
	 */

	g->average = MIRA_FP_MUL(MIRA_FP_1 - alpha, g->average);
	g->average += MIRA_FP_MUL(alpha, g->measured);

	g->stddeviation = MIRA_FP_MUL(MIRA_FP_1 - beta, g->stddeviation);
	if (g->average > g->measured)
		delta = g->average - g->measured;
	else
		delta = g->measured - g->average;
	g->stddeviation += MIRA_FP_MUL(beta, delta);

	g->average_agg = MIRA_FP_MUL(MIRA_FP_1 - alpha, g->average_agg);
	g->average_agg += MIRA_FP_MUL(alpha, agglen);

	toverhead = ieee80211_mira_toverhead(mn, ic, ni);
	toverhead = MIRA_FP_MUL(toverhead, rate);
	g->measured = MIRA_FP_DIV(MIRA_FP_1 - sfer, MIRA_FP_1 +
	    MIRA_FP_DIV(toverhead, MIRA_FP_MUL(ampdu_size, g->average_agg)));
	g->measured = MIRA_FP_MUL(g->measured, rate);
}

void
ieee80211_mira_reset_goodput_stats(struct ieee80211_mira_node *mn)
{
	int i;

	for (i = 0; i < nitems(mn->g); i++) {
		struct ieee80211_mira_goodput_stats *g = &mn->g[i];
		memset(g, 0, sizeof(*g));
		g->average_agg = 1;
		g->probe_interval = IEEE80211_MIRA_PROBE_TIMEOUT_MIN;
	}
}

void
ieee80211_mira_reset_driver_stats(struct ieee80211_mira_node *mn)
{
	mn->frames = 0;
	mn->retries = 0;
	mn->txfail = 0;
	mn->ampdu_size = 0;
	mn->agglen = 1;
}

/*
 * Rate selection.
 */

/* A rate's goodput has to be at least this much larger to be "better". */
#define IEEE80211_MIRA_RATE_THRESHOLD	(MIRA_FP_1 / 64) /* ~ 0.015 */

#define IEEE80211_MIRA_LOSS_THRESHOLD	10	/* in percent */

/* Number of (sub-)frames which render a probe valid. */
#define IEEE80211_MIRA_MIN_PROBE_FRAMES	4

/* Number of bytes which, alternatively, render a probe valid. */
#define IEEE80211_MIRA_MIN_PROBE_BYTES (2 * IEEE80211_MAX_LEN)

/* Number of Tx failures which, alternatively, render a probe valid. */
#define IEEE80211_MIRA_MAX_PROBE_TXFAIL 1

/* Number of Tx retries which, alternatively, render a probe valid. */
#define IEEE80211_MIRA_MAX_PROBE_RETRIES 4

int
ieee80211_mira_next_lower_intra_rate(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	const struct ieee80211_ht_rateset *rs;
	int i, next;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	rs = ieee80211_mira_get_rateset(ni->ni_txmcs, sgi);
	if (ni->ni_txmcs == rs->min_mcs)
		return rs->min_mcs;

	next = ni->ni_txmcs;
	for (i = rs->nrates - 1; i >= 0; i--) {
		if ((mn->valid_rates & (1 << (i + rs->min_mcs))) == 0)
			continue;
		if (i + rs->min_mcs < ni->ni_txmcs) {
			next = i + rs->min_mcs;
			break;
		}
	}

	return next;
}

int
ieee80211_mira_next_intra_rate(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	const struct ieee80211_ht_rateset *rs;
	int i, next;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	rs = ieee80211_mira_get_rateset(ni->ni_txmcs, sgi);
	if (ni->ni_txmcs == rs->max_mcs)
		return rs->max_mcs;

	next = ni->ni_txmcs;
	for (i = 0; i < rs->nrates; i++) {
		if ((mn->valid_rates & (1 << (i + rs->min_mcs))) == 0)
			continue;
		if (i + rs->min_mcs > ni->ni_txmcs) {
			next = i + rs->min_mcs;
			break;
		}
	}

	return next;
}

const struct ieee80211_ht_rateset *
ieee80211_mira_next_rateset(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	const struct ieee80211_ht_rateset *rs, *rsnext;
	int next;
	int mcs = ni->ni_txmcs;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	rs = ieee80211_mira_get_rateset(mcs, sgi);
	if (mn->probing & IEEE80211_MIRA_PROBING_UP) {
		if (rs->max_mcs == 7)	/* MCS 0-7 */
			next = sgi ? IEEE80211_HT_RATESET_MIMO2_SGI :
			    IEEE80211_HT_RATESET_MIMO2;
		else if (rs->max_mcs == 15)	/* MCS 8-15 */
			next = sgi ? IEEE80211_HT_RATESET_MIMO3_SGI :
			    IEEE80211_HT_RATESET_MIMO3;
		else if (rs->max_mcs == 23)	/* MCS 16-23 */
			next = sgi ? IEEE80211_HT_RATESET_MIMO4_SGI :
			    IEEE80211_HT_RATESET_MIMO4;
		else				/* MCS 24-31 */
			return NULL;
	} else if (mn->probing & IEEE80211_MIRA_PROBING_DOWN) {
		if (rs->min_mcs == 24)	/* MCS 24-31 */
			next = sgi ? IEEE80211_HT_RATESET_MIMO3_SGI :
			    IEEE80211_HT_RATESET_MIMO3;
		else if (rs->min_mcs == 16)	/* MCS 16-23 */
			next = sgi ? IEEE80211_HT_RATESET_MIMO2_SGI :
			    IEEE80211_HT_RATESET_MIMO2;
		else if (rs->min_mcs == 8)	/* MCS 8-15 */
			next = sgi ? IEEE80211_HT_RATESET_SISO_SGI :
			    IEEE80211_HT_RATESET_SISO;
		else				/* MCS 0-7 */
			return NULL;
	} else
		panic("%s: invalid probing mode %d", __func__, mn->probing);

	rsnext = &ieee80211_std_ratesets_11n[next];
	if ((rsnext->mcs_mask & mn->valid_rates) == 0)
		return NULL;

	return rsnext;
}

int
ieee80211_mira_best_mcs_in_rateset(struct ieee80211_mira_node *mn,
    const struct ieee80211_ht_rateset *rs)
{
	uint64_t gmax = 0;
	int i, best_mcs = rs->min_mcs;

	for (i = 0; i < rs->nrates; i++) {
		int mcs = rs->min_mcs + i;
		struct ieee80211_mira_goodput_stats *g = &mn->g[mcs];
		if (((1 << mcs) & mn->valid_rates) == 0)
			continue;
		if (g->measured > gmax + IEEE80211_MIRA_RATE_THRESHOLD) {
			gmax = g->measured;
			best_mcs = mcs;
		}
	}

	return best_mcs;
}
    
void
ieee80211_mira_probe_next_rateset(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni, const struct ieee80211_ht_rateset *rsnext)
{
	const struct ieee80211_ht_rateset *rs;
	struct ieee80211_mira_goodput_stats *g;
	int best_mcs, i;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	/* Find most recently measured best MCS from the current rateset. */
	rs = ieee80211_mira_get_rateset(ni->ni_txmcs, sgi);
	best_mcs = ieee80211_mira_best_mcs_in_rateset(mn, rs);

	/* Switch to the next rateset. */
	ni->ni_txmcs = rsnext->min_mcs;
	if ((mn->valid_rates & (1 << rsnext->min_mcs)) == 0)
		ni->ni_txmcs = ieee80211_mira_next_intra_rate(mn, ni);

	/* Select the lowest rate from the next rateset with loss-free
	 * goodput close to the current best measurement. */
	g = &mn->g[best_mcs];
	for (i = 0; i < rsnext->nrates; i++) {
		int mcs = rsnext->min_mcs + i;
		uint64_t txrate = rsnext->rates[i];

		if ((mn->valid_rates & (1 << mcs)) == 0)
			continue;

		txrate = txrate * 500; /* convert to kbit/s */
		txrate <<= MIRA_FP_SHIFT; /* convert to fixed-point */
		txrate /= 1000; /* convert to mbit/s */

		if (txrate > g->measured + IEEE80211_MIRA_RATE_THRESHOLD) {
			ni->ni_txmcs = mcs;
			break;
		}
	}

	/* Add rates from the next rateset as candidates. */
	mn->candidate_rates |= (1 << ni->ni_txmcs);
	if (mn->probing & IEEE80211_MIRA_PROBING_UP) {
		mn->candidate_rates |=
		  (1 << ieee80211_mira_next_intra_rate(mn, ni));
	} else if (mn->probing & IEEE80211_MIRA_PROBING_DOWN) {
#ifdef MIRA_AGGRESSIVE_DOWNWARDS_PROBING
		mn->candidate_rates |= ieee80211_mira_mcs_below(mn,
		    ni->ni_txmcs, sgi);
#else
		mn->candidate_rates |=
		    (1 << ieee80211_mira_next_lower_intra_rate(mn, ni));
#endif
	} else
		panic("%s: invalid probing mode %d", __func__, mn->probing);
}

int
ieee80211_mira_next_mcs(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	int next;

	if (mn->probing & IEEE80211_MIRA_PROBING_DOWN)
		next = ieee80211_mira_next_lower_intra_rate(mn, ni);
	else if (mn->probing & IEEE80211_MIRA_PROBING_UP)
		next = ieee80211_mira_next_intra_rate(mn, ni);
	else
		panic("%s: invalid probing mode %d", __func__, mn->probing);

	return next;
}

int
ieee80211_mira_prev_mcs(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	int next;

	if (mn->probing & IEEE80211_MIRA_PROBING_DOWN)
		next = ieee80211_mira_next_intra_rate(mn, ni);
	else if (mn->probing & IEEE80211_MIRA_PROBING_UP)
		next = ieee80211_mira_next_lower_intra_rate(mn, ni);
	else
		panic("%s: invalid probing mode %d", __func__, mn->probing);

	return next;
}

int
ieee80211_mira_probe_valid(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	struct ieee80211_mira_goodput_stats *g = &mn->g[ni->ni_txmcs];

	return (g->nprobes >= IEEE80211_MIRA_MIN_PROBE_FRAMES ||
	    g->nprobe_bytes >= IEEE80211_MIRA_MIN_PROBE_BYTES ||
	    mn->txfail >= IEEE80211_MIRA_MAX_PROBE_TXFAIL ||
	    mn->retries >= IEEE80211_MIRA_MAX_PROBE_RETRIES);
}

void
ieee80211_mira_probe_done(struct ieee80211_mira_node *mn)
{
	ieee80211_mira_cancel_timeouts(mn);
	ieee80211_mira_reset_driver_stats(mn);
	ieee80211_mira_reset_collision_stats(mn);
	mn->probing = IEEE80211_MIRA_NOT_PROBING;
	mn->probed_rates = 0;
	mn->candidate_rates = 0;
}

int
ieee80211_mira_intra_mode_ra_finished(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	const struct ieee80211_ht_rateset *rs;
	struct ieee80211_mira_goodput_stats *g = &mn->g[ni->ni_txmcs];
	int next_mcs, best_mcs, probed_rates;
	uint64_t next_rate;
	int sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	if (!ieee80211_mira_probe_valid(mn, ni))
		return 0;

	probed_rates = (mn->probed_rates | (1 << ni->ni_txmcs));

	/* Check if the min/max MCS in this rateset has been probed. */
	rs = ieee80211_mira_get_rateset(ni->ni_txmcs, sgi);
	if (mn->probing & IEEE80211_MIRA_PROBING_DOWN) {
		if (ni->ni_txmcs == rs->min_mcs ||
		    probed_rates & (1 << rs->min_mcs)) {
			ieee80211_mira_trigger_next_rateset(mn, ni);
			return 1;
		}
	} else if (mn->probing & IEEE80211_MIRA_PROBING_UP) {
		if (ni->ni_txmcs == rs->max_mcs ||
		    probed_rates & (1 << rs->max_mcs)) {
			ieee80211_mira_trigger_next_rateset(mn, ni);
			return 1;
		}
	}

	/*
	 * Check if the measured goodput is better than the
	 * loss-free goodput of the candidate rate.
	 */
	next_mcs = ieee80211_mira_next_mcs(mn, ni);
	if (next_mcs == ni->ni_txmcs) {
		ieee80211_mira_trigger_next_rateset(mn, ni);
		return 1;
	}
	next_rate = ieee80211_mira_get_txrate(next_mcs, sgi);
	if (g->measured >= next_rate + IEEE80211_MIRA_RATE_THRESHOLD) {
		ieee80211_mira_trigger_next_rateset(mn, ni);
		return 1;
	}

	/* Check if we had a better measurement at a previously probed MCS. */
	best_mcs = ieee80211_mira_best_mcs_in_rateset(mn, rs);
	if ((mn->probed_rates & (1 << best_mcs))) {
		if ((mn->probing & IEEE80211_MIRA_PROBING_UP) &&
		    best_mcs < ni->ni_txmcs) {
			ieee80211_mira_trigger_next_rateset(mn, ni);
			return 1;
		}
		if ((mn->probing & IEEE80211_MIRA_PROBING_DOWN) &&
		    best_mcs > ni->ni_txmcs) {
			ieee80211_mira_trigger_next_rateset(mn, ni);
			return 1;
		}
	}

	/* Check if all rates in the set of candidate rates have been probed. */
	if ((mn->candidate_rates & probed_rates) == mn->candidate_rates) {
		/* Remain in the current rateset until above checks trigger. */
		return 1;
	}

	return 0;
}

void
ieee80211_mira_trigger_next_rateset(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	const struct ieee80211_ht_rateset *rsnext;

	rsnext = ieee80211_mira_next_rateset(mn, ni);
	if (rsnext) {
		ieee80211_mira_probe_next_rateset(mn, ni, rsnext);
		mn->probing |= IEEE80211_MIRA_PROBING_INTER;
	} else
		mn->probing &= ~IEEE80211_MIRA_PROBING_INTER;
}

int
ieee80211_mira_inter_mode_ra_finished(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	return ((mn->probing & IEEE80211_MIRA_PROBING_INTER) == 0);
}

int
ieee80211_mira_best_rate(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	int i, best = 0;
	uint64_t gmax = 0;

	for (i = 0; i < nitems(mn->g); i++) {
		struct ieee80211_mira_goodput_stats *g = &mn->g[i];
		if (((1 << i) & mn->valid_rates) == 0)
			continue;
		if (g->measured > gmax + IEEE80211_MIRA_RATE_THRESHOLD) {
			gmax = g->measured;
			best = i;
		}
	}

#ifdef MIRA_DEBUG
	if (mn->best_mcs != best) {
		DPRINTF(("MCS %d is best; MCS{Mbps|probe interval}:", best));
		for (i = 0; i < IEEE80211_HT_RATESET_NUM_MCS; i++) {
			struct ieee80211_mira_goodput_stats *g = &mn->g[i];
			if ((mn->valid_rates & (1 << i)) == 0)
				continue;
			DPRINTF((" %d{%s|%dms}", i,
			    mira_fp_sprintf(g->measured),
			    g->probe_interval));
		}
		DPRINTF(("\n"));
	}
#endif
	return best;
}

/* See section 5.1.1 (at "Adaptive probing interval") in MiRA paper. */
void
ieee80211_mira_update_probe_interval(struct ieee80211_mira_node *mn,
    struct ieee80211_mira_goodput_stats *g)
{
	uint64_t lt;
	int intval;

	lt = g->loss / IEEE80211_MIRA_LOSS_THRESHOLD;
	if (lt < MIRA_FP_1)
		lt = MIRA_FP_1;
	lt >>= MIRA_FP_SHIFT; /* round to integer */

	intval = (1 << g->nprobes); /* 2^nprobes */
	if (intval > IEEE80211_MIRA_PROBE_INTVAL_MAX)
		intval = IEEE80211_MIRA_PROBE_INTVAL_MAX;

	g->probe_interval = IEEE80211_MIRA_PROBE_TIMEOUT_MIN * intval * lt;
}

void
ieee80211_mira_schedule_probe_timers(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	struct ieee80211_mira_goodput_stats *g;
	CTimeout *to;
	int mcs;

	mcs = ieee80211_mira_next_intra_rate(mn, ni);
	to = mn->probe_to[IEEE80211_MIRA_PROBE_TO_UP];
	g = &mn->g[mcs];
	if (mcs != ni->ni_txmcs && !timeout_pending(&to) &&
	    !mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_UP]) {
		timeout_add_msec(&to, g->probe_interval);
		DPRINTFN(3, ("start probing up for node %s at MCS %d in at "
		    "least %d msec\n",
		    ether_sprintf(ni->ni_macaddr), mcs, g->probe_interval));
	}

	mcs = ieee80211_mira_next_lower_intra_rate(mn, ni);
	to = mn->probe_to[IEEE80211_MIRA_PROBE_TO_DOWN];
	g = &mn->g[mcs];
	if (mcs != ni->ni_txmcs && !timeout_pending(&to) &&
	    !mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_DOWN]) {
		timeout_add_msec(&to, g->probe_interval);
		DPRINTFN(3, ("start probing down for node %s at MCS %d in at "
		    "least %d msec\n",
		    ether_sprintf(ni->ni_macaddr), mcs, g->probe_interval));
	}
}

int
ieee80211_mira_check_probe_timers(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	int ret = 0, expired_timer = IEEE80211_MIRA_PROBE_TO_INVALID;
	int mcs;

	if (mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_UP] &&
	    mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_DOWN]) {
	    	if (arc4random_uniform(2))
			expired_timer = IEEE80211_MIRA_PROBE_TO_UP;
		else
			expired_timer = IEEE80211_MIRA_PROBE_TO_DOWN;
	} else if (mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_DOWN])
		expired_timer = IEEE80211_MIRA_PROBE_TO_DOWN;
	else if (mn->probe_timer_expired[IEEE80211_MIRA_PROBE_TO_UP])
		expired_timer = IEEE80211_MIRA_PROBE_TO_UP;

	if (expired_timer != IEEE80211_MIRA_PROBE_TO_INVALID)
		mn->probe_timer_expired[expired_timer] = 0;

	switch (expired_timer) {
	case IEEE80211_MIRA_PROBE_TO_UP:
		/* Do time-based upwards probing on next frame. */
		DPRINTFN(2, ("probe timer expired: probe upwards\n"));
		mn->probing = IEEE80211_MIRA_PROBING_UP;
		mcs = ieee80211_mira_next_intra_rate(mn, ni);
		mn->candidate_rates = (1 << mcs);
		ret = 1;
		break;
	case IEEE80211_MIRA_PROBE_TO_DOWN:
		/* Do time-based downwards probing on next frame. */
		DPRINTFN(2, ("probe timer expired: probe downwards\n"));
		mn->probing = IEEE80211_MIRA_PROBING_DOWN;
		mcs = ieee80211_mira_next_lower_intra_rate(mn, ni);
		mn->candidate_rates = (1 << mcs);
		ret = 1;
		break;
	case IEEE80211_MIRA_PROBE_TO_INVALID:
	default:
		ret = 0;
		break;
	}

	return ret;
}

void
ieee80211_mira_probe_next_rate(struct ieee80211_mira_node *mn,
    struct ieee80211_node *ni)
{
	struct ieee80211_mira_goodput_stats *gprev, *g;
	int prev_mcs;

	prev_mcs = ieee80211_mira_prev_mcs(mn, ni);
	gprev = &mn->g[prev_mcs];
	g = &mn->g[ni->ni_txmcs];
	/* If the previous rate was worse, increase its probing interval. */
	if (prev_mcs != ni->ni_txmcs &&
	    gprev->measured + IEEE80211_MIRA_RATE_THRESHOLD < g->measured)
		ieee80211_mira_update_probe_interval(mn, gprev);

	/* Select the next rate to probe. */
	mn->probed_rates |= (1 << ni->ni_txmcs);
	ni->ni_txmcs = ieee80211_mira_next_mcs(mn, ni);
}

int
ieee80211_mira_valid_tx_mcs(struct ieee80211com *ic, int mcs)
{
	uint32_t ntxstreams = 1;
	static const int max_mcs[] = { 7, 15, 23, 31 };

	if ((ic->ic_tx_mcs_set & IEEE80211_TX_RX_MCS_NOT_EQUAL) == 0)
		return isset(ic->ic_sup_mcs, mcs);

	ntxstreams += ((ic->ic_tx_mcs_set & IEEE80211_TX_SPATIAL_STREAMS) >> 2);
	if (ntxstreams < 1 || ntxstreams > 4)
		panic("invalid number of Tx streams: %u", ntxstreams);
	return (mcs <= max_mcs[ntxstreams - 1] && isset(ic->ic_sup_mcs, mcs));
}

uint32_t
ieee80211_mira_valid_rates(struct ieee80211com *ic, struct ieee80211_node *ni)
{
	uint32_t valid_mcs = 0;
	int i;

	for (i = 0; i < IEEE80211_HT_RATESET_NUM_MCS; i++) {
		if (!isset(ni->ni_rxmcs, i))
			continue;
		if (!ieee80211_mira_valid_tx_mcs(ic, i))
			continue;
		valid_mcs |= (1 << i);
	}

	return valid_mcs;
}

uint32_t
ieee80211_mira_mcs_below(struct ieee80211_mira_node *mn, int mcs, int sgi)
{
	const struct ieee80211_ht_rateset *rs;
	uint32_t mcs_mask;
	int i;

	rs = ieee80211_mira_get_rateset(mcs, sgi);
	mcs_mask = (1 << rs->min_mcs);
	for (i = rs->min_mcs + 1; i < mcs; i++) {
		if ((mn->valid_rates & (1 << i)) == 0)
			continue;
		mcs_mask |= (1 << i);
	}

	return mcs_mask;
}

/*
 * Constants involved in detecting suspected frame collisions.
 * See section 5.2 of MiRA paper
 */
#define MIRA_COLLISION_LOSS_PERCENTAGE	10	/* from MiRA paper */
#define MIRA_COLLISION_DETECTED		3	/* from MiRA paper */

/*
 * XXX The paper's algorithm assumes aggregated frames. This is particularly
 * important for the detection of consecutive frame collisions which indicate
 * high competition for air time. Because we do not yet support Tx aggregation,
 * we run the algorithm over the result of several frames instead.
 * We also aggregate retries across all frames and act upon a percentage of
 * retried frames, rather than acting on retries seen for one aggregated frame.
 *
 * The collision window size (number of frames sent) needs to be short to
 * ensure our detection of consecutive collisions remains somewhat accurate.
 * We really have no idea how much time passes between frames in the window!
 * The good news is that users will only care about collision detection during
 * a transmit burst anyway, and we have this case more or less covered.
 */
#define MIRA_COLLISION_MIN_FRAMES	6	/* XXX magic number */
#define MIRA_COLLISION_RETRY_PERCENTAGE	60	/* XXX magic number */

/* Set RTS threshold based on suspected collision from other STAs. */
void
ieee80211_mira_set_rts_threshold(struct ieee80211_mira_node *mn,
    struct ieee80211com *ic, struct ieee80211_node *ni)
{
	uint16_t rtsthreshold = mn->rts_threshold;
	uint32_t loss, retry;

	/* Update collision window stats. */
	mn->ifwnd_frames += mn->frames;
	mn->ifwnd_retries += mn->retries;
	mn->ifwnd_txfail += mn->txfail;
	if (mn->ifwnd_frames < MIRA_COLLISION_MIN_FRAMES)
		return; /* not enough frames yet */

	/* Check whether the loss pattern indicates frame collisions. */
	loss = (mn->ifwnd_txfail * 100) / mn->ifwnd_frames;
	retry = (mn->ifwnd_retries * 100) / mn->ifwnd_frames;
	if (retry > MIRA_COLLISION_RETRY_PERCENTAGE &&
	    loss < MIRA_COLLISION_LOSS_PERCENTAGE) {
		if (mn->ifwnd == 0) {
			/* First frame collision confirmed. */
			mn->ifwnd = MIRA_COLLISION_DETECTED;
		} else if (mn->ifwnd == MIRA_COLLISION_DETECTED) {
			/* Successive frame collision confirmed. Use RTS. */
			rtsthreshold = IEEE80211_RTS_DEFAULT;
		}
	} else {
		if (mn->ifwnd > 0)
			mn->ifwnd--;
		if (mn->ifwnd == 0)
			rtsthreshold = IEEE80211_RTS_MAX;
	}

	mn->rts_threshold = rtsthreshold;
	ieee80211_mira_reset_collision_stats(mn);
}

int
ieee80211_mira_get_rts_threshold(struct ieee80211_mira_node *mn,
    struct ieee80211com *ic, struct ieee80211_node *ni, size_t framelen)
{
	int rtsrate = ieee80211_min_basic_rate(ic);
	uint64_t txtime, rtsoverhead;
	/* Magic number from MiRA paper ("cost/benefit ratio"). */
	static const uint64_t k = MIRA_FP_1 + (MIRA_FP_1 / 2); /* 1.5 */

	if (mn->probing || mn->rts_threshold >= IEEE80211_RTS_MAX)
		return IEEE80211_RTS_MAX;

	/* Use RTS only if potential gains outweigh overhead. */
	txtime = ieee80211_mira_ht_txtime(framelen, ni->ni_txmcs,
	    IEEE80211_IS_CHAN_2GHZ(ni->ni_chan),
	    (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0);
	rtsoverhead = ieee80211_mira_legacy_txtime(MIRA_RTSLEN, rtsrate, ic);
	rtsoverhead += ieee80211_mira_legacy_txtime(MIRA_CTSLEN, rtsrate, ic);
	/* convert to fixed-point */
	txtime <<= MIRA_FP_SHIFT;
	rtsoverhead <<= MIRA_FP_SHIFT;
	if (txtime >= MIRA_FP_MUL(k, rtsoverhead))
		return mn->rts_threshold;

	return IEEE80211_RTS_MAX;
}

void
ieee80211_mira_reset_collision_stats(struct ieee80211_mira_node *mn)
{
	mn->ifwnd_frames = 0;
	mn->ifwnd_retries = 0;
	mn->ifwnd_txfail = 0;
}

void
ieee80211_mira_choose(struct ieee80211_mira_node *mn, struct ieee80211com *ic,
    struct ieee80211_node *ni)
{
	struct ieee80211_mira_goodput_stats *g = &mn->g[ni->ni_txmcs];
	int s, sgi = (ni->ni_flags & IEEE80211_NODE_HT_SGI20) ? 1 : 0;

	s = splnet();

	if (mn->valid_rates == 0)
		mn->valid_rates = ieee80211_mira_valid_rates(ic, ni);

#ifdef MIRA_DEBUG
	if (mira_debug >= 5)
		mira_print_driver_stats(mn, ni);
#endif
	ieee80211_mira_update_stats(mn, ic, ni);

	if (mn->probing) {
		/* Probe another rate or settle at the best rate. */
		if (!ieee80211_mira_intra_mode_ra_finished(mn, ni)) {
			if (ieee80211_mira_probe_valid(mn, ni)) {
				ieee80211_mira_probe_next_rate(mn, ni);
				ieee80211_mira_reset_driver_stats(mn);
			}
			DPRINTFN(4, ("probing MCS %d\n", ni->ni_txmcs));
		} else if (ieee80211_mira_inter_mode_ra_finished(mn, ni)) {
			int best = ieee80211_mira_best_rate(mn, ni);
			if (mn->best_mcs != best) {
				mn->best_mcs = best;
				ni->ni_txmcs = best;
				/* Reset probe interval for new best rate. */
				mn->g[best].probe_interval =
				    IEEE80211_MIRA_PROBE_TIMEOUT_MIN;
				mn->g[best].nprobes = 0;
				mn->g[best].nprobe_bytes = 0;
			} else
				ni->ni_txmcs = mn->best_mcs;
			ieee80211_mira_probe_done(mn);
		}

		splx(s);
		return;
	} else {
		ieee80211_mira_set_rts_threshold(mn, ic, ni);
		ieee80211_mira_reset_driver_stats(mn);
		ieee80211_mira_schedule_probe_timers(mn, ni);
	}

	if (ieee80211_mira_check_probe_timers(mn, ni)) {
		/* Time-based probing has triggered. */
		splx(s);
		return;
	}

	/* Check if event-based probing should be triggered. */
	if (g->measured <= g->average - 2 * g->stddeviation) {
		/* Channel becomes bad. Probe downwards. */
		DPRINTFN(2, ("channel becomes bad; probe downwards\n"));
		DPRINTFN(3, ("measured: %s Mbit/s\n",
		    mira_fp_sprintf(g->measured)));
		DPRINTFN(3, ("average: %s Mbit/s\n",
		    mira_fp_sprintf(g->average)));
		DPRINTFN(3, ("stddeviation: %s\n",
		    mira_fp_sprintf(g->stddeviation)));
		mn->probing = IEEE80211_MIRA_PROBING_DOWN;
		mn->probed_rates = 0;
#ifdef MIRA_AGGRESSIVE_DOWNWARDS_PROBING
		/* Allow for probing all the way down within this rateset. */
		mn->candidate_rates = ieee80211_mira_mcs_below(mn,
		    ni->ni_txmcs, sgi);
#else
		/* Probe the lower candidate rate to see if it's any better. */
		mn->candidate_rates =
		    (1 << ieee80211_mira_next_lower_intra_rate(mn, ni));
#endif
	} else if (g->measured >= g->average + 2 * g->stddeviation) {
		/* Channel becomes good. */
		DPRINTFN(2, ("channel becomes good; probe upwards\n"));
		DPRINTFN(3, ("measured: %s Mbit/s\n",
		    mira_fp_sprintf(g->measured)));
		DPRINTFN(3, ("average: %s Mbit/s\n",
		    mira_fp_sprintf(g->average)));
		DPRINTFN(3, ("stddeviation: %s\n",
		    mira_fp_sprintf(g->stddeviation)));
		mn->probing = IEEE80211_MIRA_PROBING_UP;
		mn->probed_rates = 0;
		/* Probe the upper candidate rate to see if it's any better. */
		mn->candidate_rates =
		    (1 << ieee80211_mira_next_intra_rate(mn, ni));
	} else {
		/* Remain at current rate. */
		mn->probing = IEEE80211_MIRA_NOT_PROBING;
		mn->probed_rates = 0;
		mn->candidate_rates = 0;
	}

	splx(s);
}

void
ieee80211_mira_node_init(struct ieee80211_mira_node *mn)
{
	memset(mn, 0, sizeof(*mn));
	mn->agglen = 1;
	mn->rts_threshold = IEEE80211_RTS_MAX;
	ieee80211_mira_reset_goodput_stats(mn);
	ieee80211_mira_reset_collision_stats(mn);

	timeout_set(&mn->probe_to[IEEE80211_MIRA_PROBE_TO_UP],
	    ieee80211_mira_probe_timeout_up, mn);
	timeout_set(&mn->probe_to[IEEE80211_MIRA_PROBE_TO_DOWN],
	    ieee80211_mira_probe_timeout_down, mn);
}

void
ieee80211_mira_cancel_timeouts(struct ieee80211_mira_node *mn)
{
	int t;

	for (t = 0; t < nitems(mn->probe_to); t++)
		timeout_del(&mn->probe_to[t]);
}
