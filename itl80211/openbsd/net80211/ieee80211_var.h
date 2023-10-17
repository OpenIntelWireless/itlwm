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
/*	$OpenBSD: ieee80211_var.h,v 1.97 2019/07/29 10:50:09 stsp Exp $	*/
/*	$NetBSD: ieee80211_var.h,v 1.7 2004/05/06 03:07:10 dyoung Exp $	*/

/*-
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002, 2003 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net80211/ieee80211_var.h,v 1.15 2004/04/05 22:10:26 sam Exp $
 */
#ifndef _NET80211_IEEE80211_VAR_H_
#define _NET80211_IEEE80211_VAR_H_

/*
 * Definitions for IEEE 802.11 drivers.
 */

#define explicit_bzero bzero
#define nitems(arr) (sizeof(arr) / sizeof((arr)[0]))



#ifdef	SMALL_KERNEL
#define IEEE80211_STA_ONLY	1
#endif

#include <sys/param.h>
#include <sys/timeout.h>
#include <sys/_if_ether.h>
#include <sys/_if_media.h>
#include <sys/_arc4random.h>
#include <sys/_task.h>
#include <sys/_ifq.h>
#include <sys/_malloc.h>

#include <sys/kpi_mbuf.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_crypto.h>
#include <net80211/ieee80211_ioctl.h>		/* for ieee80211_stats */
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_proto.h>

#include <IOKit/IOLib.h>

#define IEEE80211_DEBUG

#define _KASSERT(exp) KASSERT(exp, "")

#define CLUSTER_SIZE 4096

#define    ALIGNED_POINTER(p,t)    1

extern int TX_TYPE_MGMT;

extern int TX_TYPE_FRAME;

extern int _stop(struct kmod_info*, void*);

extern int _start(struct kmod_info*, void*);

extern int timingsafe_bcmp(const void *b1, const void *b2, size_t n);

/*
 * ppsratecheck(): packets (or events) per second limitation.
 */
static int
ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
    struct timeval tv, delta;
    int rv;

    microuptime(&tv);

    timersub(&tv, lasttime, &delta);

    /*
     * check for 0,0 is so that the message will be seen at least once.
     * if more than one second have passed since the last update of
     * lasttime, reset the counter.
     *
     * we do increment *curpps even in *curpps < maxpps case, as some may
     * try to use *curpps for stat purposes as well.
     */
    if (maxpps == 0)
        rv = 0;
    else if ((lasttime->tv_sec == 0 && lasttime->tv_usec == 0) ||
        delta.tv_sec >= 1) {
        *lasttime = tv;
        *curpps = 0;
        rv = 1;
    } else if (maxpps < 0)
        rv = 1;
    else if (*curpps < maxpps)
        rv = 1;
    else
        rv = 0;

#if 1 /*DIAGNOSTIC?*/
    /* be careful about wrap-around */
    if (*curpps + 1 > *curpps)
        *curpps = *curpps + 1;
#else
    /*
     * assume that there's not too many calls to this function.
     * not sure if the assumption holds, as it depends on *caller's*
     * behavior, not the behavior of this function.
     * IMHO it is wrong to make assumption on the caller's behavior,
     * so the above #if is #if 1, not #ifdef DIAGNOSTIC.
     */
    *curpps = *curpps + 1;
#endif
    
    return (rv);
}

/*
 * ratecheck(): simple time-based rate-limit checking.  see ratecheck(9)
 * for usage and rationale.
 */
static int
ratecheck(struct timeval *lasttime, const struct timeval *mininterval)
{
    struct timeval tv, delta;
    int rv = 0;

    getmicrouptime(&tv);

    timersub(&tv, lasttime, &delta);

    /*
     * check for 0,0 is so that the message will be seen at least once,
     * even if interval is huge.
     */
    if (timercmp(&delta, mininterval, >=) ||
        (lasttime->tv_sec == 0 && lasttime->tv_usec == 0)) {
        *lasttime = tv;
        rv = 1;
    }

    return (rv);
}

static u_int32_t ether_crc32_le_update(u_int32_t crc, const u_int8_t *buf, size_t len)
{
    static const u_int32_t crctab[] = {
        0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
        0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
        0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
        0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
    };
    size_t i;

    for (i = 0; i < len; i++) {
        crc ^= buf[i];
        crc = (crc >> 4) ^ crctab[crc & 0xf];
        crc = (crc >> 4) ^ crctab[crc & 0xf];
    }

    return (crc);
}

static char* ether_sprintf(const uint8_t *ap)
{
         static char etherbuf[18];
         snprintf(etherbuf, sizeof (etherbuf), "%6D", ap, ":");
         return (etherbuf);
}

static void array_sprintf(char *output, uint8_t output_size, const uint8_t *array, const uint8_t len)
{
    uint8_t index = 0;
    for (index = 0; index < len; index++) {
        snprintf(output, output_size, "0x%02x ", array++);
    }
}

#define	IEEE80211_CHAN_MAX	255
#define	IEEE80211_CHAN_ANY	0xffff		/* token for ``any channel'' */
#define	IEEE80211_CHAN_ANYC \
	((struct ieee80211_channel *) NULL)

#define	IEEE80211_TXPOWER_MAX	100	/* max power */
#define	IEEE80211_TXPOWER_MIN	-50	/* kill radio (if possible) */

#define IEEE80211_RSSI_THRES_2GHZ		(-60)	/* in dBm */
#define IEEE80211_RSSI_THRES_5GHZ		(-70)	/* in dBm */
#define IEEE80211_RSSI_THRES_RATIO_2GHZ		50	/* in percent */
#define IEEE80211_RSSI_THRES_RATIO_5GHZ		40	/* in percent */

#define IEEE80211_BGSCAN_FAIL_MAX		360	/* units of 500 msec */

/*
 * Missed beacon threshold: An access point has disappeared if this amount
 * of consecutive beacons have been missed.
 * This value needs to be high enough to avoid frequent re-connects to APs
 * which suffer from occasional packet loss, and low enough to avoid a long
 * delay before we start scanning when an AP has actually disappeared.
 *
 * The beacon interval is variable, but generally in the order of 100ms.
 * So 30 beacons implies a grace period of about 3 seconds before we start
 * searching for a new AP.
 */
#define IEEE80211_BEACON_MISS_THRES        30    /* units of beacons */

enum ieee80211_phytype {
	IEEE80211_T_DS,			/* direct sequence spread spectrum */
	IEEE80211_T_OFDM,		/* frequency division multiplexing */
	IEEE80211_T_XR		        /* extended range mode */
};
#define	IEEE80211_T_CCK	IEEE80211_T_DS	/* more common nomenclature */

/* XXX not really a mode; there are really multiple PHY's */
enum ieee80211_phymode {
	IEEE80211_MODE_AUTO	= 0,	/* autoselect */
	IEEE80211_MODE_11A	= 1,	/* 5GHz, OFDM */
	IEEE80211_MODE_11B	= 2,	/* 2GHz, CCK */
	IEEE80211_MODE_11G	= 3,	/* 2GHz, OFDM */
	IEEE80211_MODE_11N	= 4,	/* 2GHz/5GHz, OFDM/HT */
	IEEE80211_MODE_11AC	= 5,	/* 5GHz, OFDM/VHT */
    IEEE80211_MODE_11AX = 6,    /* 5GHz, 6GHz, HE */
};
#define	IEEE80211_MODE_MAX	(IEEE80211_MODE_11AX+1)

enum ieee80211_opmode {
	IEEE80211_M_STA		= 1,	/* infrastructure station */
#ifndef IEEE80211_STA_ONLY
	IEEE80211_M_IBSS	= 0,	/* IBSS (adhoc) station */
	IEEE80211_M_AHDEMO	= 3,	/* Old lucent compatible adhoc demo */
	IEEE80211_M_HOSTAP	= 6,	/* Software Access Point */
#endif
	IEEE80211_M_MONITOR	= 8	/* Monitor mode */
};

/*
 * 802.11g protection mode.
 */
enum ieee80211_protmode {
	IEEE80211_PROT_NONE	= 0,	/* no protection */
	IEEE80211_PROT_CTSONLY	= 1,	/* CTS to self */
	IEEE80211_PROT_RTSCTS	= 2	/* RTS-CTS */
};

/*
 * Channels are specified by frequency and attributes.
 */
struct ieee80211_channel {
	u_int16_t	ic_freq;	/* setting in MHz */
	u_int32_t	ic_flags;	/* see below */
    u_int16_t   ic_center_freq1;
    u_int16_t   ic_center_freq2;
};

/*
 * Channel attributes (XXX must keep in sync with radiotap flags).
 */
#define IEEE80211_CHAN_CCK	0x0020	/* CCK channel */
#define IEEE80211_CHAN_OFDM	0x0040	/* OFDM channel */
#define IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel */
#define IEEE80211_CHAN_5GHZ	0x0100	/* 5 GHz spectrum channel */
#define IEEE80211_CHAN_PASSIVE	0x0200	/* Only passive scan allowed */
#define IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define IEEE80211_CHAN_XR	0x1000	/* Extended range OFDM channel */

#define IEEE80211_CHAN_HT20    0x00010000 /* HT 20 channel */
#define IEEE80211_CHAN_HT40U    0x00020000 /* HT 40 channel w/ ext above */
#define IEEE80211_CHAN_HT40D    0x00040000 /* HT 40 channel w/ ext below */
#define IEEE80211_CHAN_DFS    0x00080000 /* DFS required */
#define IEEE80211_CHAN_4MSXMIT    0x00100000 /* 4ms limit on frame length */
#define IEEE80211_CHAN_NOADHOC    0x00200000 /* adhoc mode not allowed */
#define IEEE80211_CHAN_NOHOSTAP    0x00400000 /* hostap mode not allowed */
#define IEEE80211_CHAN_11D    0x00800000 /* 802.11d required */
#define IEEE80211_CHAN_VHT20    0x01000000 /* VHT20 channel */
#define IEEE80211_CHAN_VHT40U    0x02000000 /* VHT40 channel, ext above */
#define IEEE80211_CHAN_VHT40D    0x04000000 /* VHT40 channel, ext below */
#define IEEE80211_CHAN_VHT80    0x08000000 /* VHT80 channel */
#define IEEE80211_CHAN_VHT160    0x10000000 /* VHT160 channel */
#define IEEE80211_CHAN_VHT80_80    0x20000000 /* VHT80+80 channel */

#define IEEE80211_CHAN_HT40    (IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D)
#define IEEE80211_CHAN_HT    (IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40)

#define IEEE80211_CHAN_VHT40    (IEEE80211_CHAN_VHT40U | IEEE80211_CHAN_VHT40D)
#define IEEE80211_CHAN_VHT    (IEEE80211_CHAN_VHT20 | IEEE80211_CHAN_VHT40 \
                | IEEE80211_CHAN_VHT80 | IEEE80211_CHAN_VHT80_80 \
                | IEEE80211_CHAN_VHT160)

#define IEEE80211_CHAN_ALL  \
    (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ | \
    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_PASSIVE | IEEE80211_CHAN_DYN | IEEE80211_CHAN_XR | \
    IEEE80211_CHAN_HT | IEEE80211_CHAN_VHT)

/*
 * Useful combinations of channel characteristics.
 */
#define IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define	IEEE80211_IS_CHAN_A(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_B(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_N(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_HT) != 0)
#define	IEEE80211_IS_CHAN_AC(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_VHT) != 0)

#define	IEEE80211_IS_CHAN_2GHZ(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
#define	IEEE80211_IS_CHAN_5GHZ(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_5GHZ) != 0)
#define	IEEE80211_IS_CHAN_OFDM(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_OFDM) != 0)
#define	IEEE80211_IS_CHAN_CCK(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_CCK) != 0)
#define	IEEE80211_IS_CHAN_XR(_c) \
	(((_c)->ic_flags & IEEE80211_CHAN_XR) != 0)

/*
 * EDCA AC parameters.
 */
struct ieee80211_edca_ac_params {
	u_int8_t	ac_ecwmin;	/* CWmin = 2^ECWmin - 1 */
	u_int8_t	ac_ecwmax;	/* CWmax = 2^ECWmax - 1 */
	u_int8_t	ac_aifsn;
	u_int16_t	ac_txoplimit;	/* 32TU */
#define IEEE80211_TXOP_TO_US(txop)	((txop) * 32)

	u_int8_t	ac_acm;
};

extern const struct ieee80211_edca_ac_params
	    ieee80211_edca_table[IEEE80211_MODE_MAX][EDCA_NUM_AC];
extern const struct ieee80211_edca_ac_params
	    ieee80211_qap_edca_table[IEEE80211_MODE_MAX][EDCA_NUM_AC];

#define IEEE80211_DEFRAG_SIZE	3	/* must be >= 3 according to spec */
/*
 * Entry in the fragment cache.
 */
struct ieee80211_defrag {
	CTimeout*	df_to;
	mbuf_t df_m;
	u_int16_t	df_seq;
	u_int8_t	df_frag;
};

#define IEEE80211_PROTO_NONE	0
#define IEEE80211_PROTO_RSN	(1 << 0)
#define IEEE80211_PROTO_WPA	(1 << 1)

#define	IEEE80211_SCAN_UNLOCKED	0x0
#define	IEEE80211_SCAN_LOCKED	0x1
#define	IEEE80211_SCAN_REQUEST	0x2
#define	IEEE80211_SCAN_RESUME	0x4

#define IEEE80211_GROUP_NKID	6

struct ieee80211com {
	struct arpcom		ic_ac;
	LIST_ENTRY(ieee80211com) ic_list;	/* chain of all ieee80211com */
	void			(*ic_recv_mgmt)(struct ieee80211com *,
				    mbuf_t, struct ieee80211_node *,
				    struct ieee80211_rxinfo *, int);
	int			(*ic_send_mgmt)(struct ieee80211com *,
				    struct ieee80211_node *, int, int, int);
	int			(*ic_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
	int			(*ic_newauth)(struct ieee80211com *,
				    struct ieee80211_node *, int, uint16_t);
	void			(*ic_newassoc)(struct ieee80211com *,
				    struct ieee80211_node *, int);
	void			(*ic_node_leave)(struct ieee80211com *,
				    struct ieee80211_node *);
	void			(*ic_updateslot)(struct ieee80211com *);
	void			(*ic_updateedca)(struct ieee80211com *);
    void            (*ic_updatedtim)(struct ieee80211com *);
	void			(*ic_set_tim)(struct ieee80211com *, int, int);
	int			(*ic_set_key)(struct ieee80211com *,
				    struct ieee80211_node *,
				    struct ieee80211_key *);
	void			(*ic_delete_key)(struct ieee80211com *,
				    struct ieee80211_node *,
				    struct ieee80211_key *);
	int			(*ic_ampdu_tx_start)(struct ieee80211com *,
				    struct ieee80211_node *, u_int8_t);
	void			(*ic_ampdu_tx_stop)(struct ieee80211com *,
				    struct ieee80211_node *, u_int8_t);
	int			(*ic_ampdu_rx_start)(struct ieee80211com *,
				    struct ieee80211_node *, u_int8_t);
	void			(*ic_ampdu_rx_stop)(struct ieee80211com *,
				    struct ieee80211_node *, u_int8_t);
	void			(*ic_updateprot)(struct ieee80211com *);
	int			(*ic_bgscan_start)(struct ieee80211com *);
    /* The channel width has changed (20<->2040) */
    void            (*ic_update_chw)(struct ieee80211com *);
    void            (*ic_event_handler)(struct ieee80211com *, int, void *);
	CTimeout*		ic_bgscan_timeout;
	uint32_t		ic_bgscan_fail;
	u_int8_t		ic_myaddr[IEEE80211_ADDR_LEN];
	struct ieee80211_rateset ic_sup_rates[IEEE80211_MODE_MAX];
	struct ieee80211_channel ic_channels[IEEE80211_CHAN_MAX+1];
	u_char			ic_chan_avail[howmany(IEEE80211_CHAN_MAX,NBBY)];
	u_char			ic_chan_active[howmany(IEEE80211_CHAN_MAX, NBBY)];
	u_char			ic_chan_scan[howmany(IEEE80211_CHAN_MAX,NBBY)];
	struct mbuf_queue	ic_mgtq;
	struct mbuf_queue	ic_pwrsaveq;
	u_int8_t		ic_scan_count;	/* count scans */
	u_int32_t		ic_flags;	/* state flags */
	u_int32_t		ic_xflags;	/* more flags */
    
	u_int32_t		ic_userflags;	/* yet more flags */
	u_int32_t		ic_caps;	/* capabilities */
	u_int16_t		ic_modecaps;	/* set of mode capabilities */
	u_int16_t		ic_curmode;	/* current mode */
	enum ieee80211_phytype	ic_phytype;	/* XXX wrong for multi-mode */
	enum ieee80211_opmode	ic_opmode;	/* operation mode */
	enum ieee80211_state	ic_state;	/* 802.11 state */
	u_int32_t		*ic_aid_bitmap;
	u_int16_t		ic_max_aid;
	enum ieee80211_protmode	ic_protmode;	/* 802.11g/n protection mode */
	struct ifmedia		ic_media;	/* interface media config */
	caddr_t			ic_rawbpf;	/* packet filter structure */
	struct ieee80211_node	*ic_bss;	/* information for this node */
	struct ieee80211_channel *ic_ibss_chan;
	int			ic_fixed_rate;	/* index to ic_sup_rates[] */
	u_int16_t		ic_rtsthreshold;
	u_int16_t		ic_fragthreshold;
	u_int			ic_scangen;	/* gen# for timeout scan */
	struct ieee80211_node	*(*ic_node_alloc)(struct ieee80211com *);
	void			(*ic_node_free)(struct ieee80211com *,
					struct ieee80211_node *);
	void			(*ic_node_copy)(struct ieee80211com *,
					struct ieee80211_node *,
					const struct ieee80211_node *);
	u_int8_t		(*ic_node_getrssi)(struct ieee80211com *,
					const struct ieee80211_node *);
	int			(*ic_node_checkrssi)(struct ieee80211com *,
					const struct ieee80211_node *);
	u_int8_t		ic_max_rssi;
	struct ieee80211_tree	ic_tree;
	int			ic_nnodes;	/* length of ic_nnodes */
	int			ic_max_nnodes;	/* max length of ic_nnodes */
	u_int16_t		ic_lintval;	/* listen interval */
	int16_t			ic_txpower;	/* tx power setting (dBm) */
	int			ic_bmissthres;	/* beacon miss threshold */
	int			ic_mgt_timer;	/* mgmt timeout */
#ifndef IEEE80211_STA_ONLY
	CTimeout*		ic_inact_timeout; /* node inactivity timeout */
	CTimeout*		ic_node_cache_timeout;
#endif
	int			ic_des_esslen;
	u_int8_t		ic_des_essid[IEEE80211_NWID_LEN];
	struct ieee80211_channel *ic_des_chan;	/* desired channel */
	u_int8_t		ic_des_bssid[IEEE80211_ADDR_LEN];
#ifdef USE_APPLE_SUPPLICANT
	u_int8_t		ic_rsn_ie_override[257];
#endif
    u_int16_t       ic_deauth_reason;
    u_int16_t       ic_assoc_status;
	struct ieee80211_key	ic_nw_keys[IEEE80211_GROUP_NKID];
	int			ic_def_txkey;	/* group data key index */
#define ic_wep_txkey	ic_def_txkey
	int			ic_igtk_kid;	/* IGTK key index */
	u_int32_t		ic_iv;		/* initial vector for wep */
	struct ieee80211_stats	ic_stats;	/* statistics */
	struct timeval		ic_last_merge_print;	/* for rate-limiting
							 * IBSS merge print-outs
							 */
	struct ieee80211_edca_ac_params ic_edca_ac[EDCA_NUM_AC];
	u_int			ic_edca_updtcount;
	u_int16_t		ic_tid_noack;
	u_int8_t		ic_globalcnt[EAPOL_KEY_NONCE_LEN];
	u_int8_t		ic_nonce[EAPOL_KEY_NONCE_LEN];
	u_int8_t		ic_psk[IEEE80211_PMK_LEN];
	CTimeout*		ic_rsn_timeout;
	int			ic_tkip_micfail;
	u_int64_t		ic_tkip_micfail_last_tsc;
#ifndef IEEE80211_STA_ONLY
	CTimeout*		ic_tkip_micfail_timeout;
#endif

	TAILQ_HEAD(, ieee80211_pmk) ic_pmksa;	/* PMKSA cache */
	u_int			ic_rsnprotos;
	u_int			ic_rsnakms;
	u_int			ic_rsnciphers;
	enum ieee80211_cipher	ic_rsngroupcipher;
	enum ieee80211_cipher	ic_rsngroupmgmtcipher;

#ifdef notyet
	struct ieee80211_defrag	ic_defrag[IEEE80211_DEFRAG_SIZE];
	int			ic_defrag_cur;
#endif

	u_int8_t		*ic_tim_bitmap;
	u_int			ic_tim_len;
	u_int			ic_tim_mcast_pending;
	u_int			ic_dtim_period;
	u_int			ic_dtim_count;

	u_int32_t		ic_txbfcaps;
	u_int16_t		ic_htcaps;
    uint32_t        ic_vhtcaps;
    uint32_t        ic_hecaps;
	u_int8_t		ic_ampdu_params;
	u_int8_t		ic_sup_mcs[howmany(80, NBBY)];
	u_int16_t		ic_max_rxrate;	/* in Mb/s, 0 <= rate <= 1023 */
	u_int8_t		ic_tx_mcs_set;
	u_int16_t		ic_htxcaps;
	u_int8_t		ic_aselcaps;
	u_int8_t		ic_dialog_token;
	int			ic_fixed_mcs;
    uint64_t        ic_last_cache_scan_ts;
    uint16_t        ic_vht_tx_mcs_map;
    uint16_t        ic_vht_rx_mcs_map;
    uint16_t        ic_vht_tx_highest;
    uint16_t        ic_vht_rx_highest;
    uint16_t        ic_vht_sup_mcs[howmany(80, NBBY)];
    
    /* HE state */
    struct ieee80211_he_cap_elem ic_he_cap_elem;   /* Fixed portion of the HE capabilities element. */
    struct ieee80211_he_mcs_nss_supp ic_he_mcs_nss_supp;   /* The supported NSS/MCS combinations. */
    uint8_t ic_ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN]; /* Holds the PPE Thresholds data. */
    
	TAILQ_HEAD(, ieee80211_ess)	 ic_ess;
};
#define	ic_if		ic_ac.ac_if
#define	ic_softc	ic_if.if_softc

/* list of APs we want to automatically use */
/* all data is copied from struct ieee80211com */
struct ieee80211_ess {
	/* nwid */
	int			esslen;
	u_int8_t		essid[IEEE80211_NWID_LEN];

	/* clear/wep/wpa */
	u_int32_t		flags;

	/* nwkey */
	struct ieee80211_key    nw_keys[IEEE80211_GROUP_NKID];
	int			def_txkey;

	/* wpakey */
	u_int8_t		psk[IEEE80211_PMK_LEN];
	u_int			rsnprotos;
	u_int			rsnakms;
	u_int			rsnciphers;
	enum ieee80211_cipher	rsngroupcipher;

	TAILQ_ENTRY(ieee80211_ess) ess_next;
};

#define	IEEE80211_ADDR_EQ(a1,a2)	(memcmp(a1,a2,IEEE80211_ADDR_LEN) == 0)
#define	IEEE80211_ADDR_COPY(dst,src)	memcpy(dst,src,IEEE80211_ADDR_LEN)

/* ic_flags */
#define	IEEE80211_F_ASCAN	0x00000001	/* STATUS: active scan */
#define	IEEE80211_F_SIBSS	0x00000002	/* STATUS: start IBSS */
#define	IEEE80211_F_WEPON	0x00000100	/* CONF: WEP enabled */
#define	IEEE80211_F_IBSSON	0x00000200	/* CONF: IBSS creation enable */
#define	IEEE80211_F_PMGTON	0x00000400	/* CONF: Power mgmt enable */
#define	IEEE80211_F_DESBSSID	0x00000800	/* CONF: des_bssid is set */
#define	IEEE80211_F_ROAMING	0x00002000	/* CONF: roaming enabled */
#define	IEEE80211_F_TXPMGT	0x00018000	/* STATUS: tx power */
#define IEEE80211_F_TXPOW_OFF	0x00000000	/* TX Power: radio disabled */
#define IEEE80211_F_TXPOW_FIXED	0x00008000	/* TX Power: fixed rate */
#define IEEE80211_F_TXPOW_AUTO	0x00010000	/* TX Power: undefined */
#define	IEEE80211_F_SHSLOT	0x00020000	/* STATUS: short slot time */
#define	IEEE80211_F_SHPREAMBLE	0x00040000	/* STATUS: short preamble */
#define IEEE80211_F_QOS		0x00080000	/* CONF: QoS enabled */
#define	IEEE80211_F_USEPROT	0x00100000	/* STATUS: protection enabled */
#define	IEEE80211_F_RSNON	0x00200000	/* CONF: RSN enabled */
#define	IEEE80211_F_PSK		0x00400000	/* CONF: pre-shared key set */
#define IEEE80211_F_COUNTERM	0x00800000	/* STATUS: countermeasures */
#define IEEE80211_F_MFPR	0x01000000	/* CONF: MFP required */
#define	IEEE80211_F_HTON	0x02000000	/* CONF: HT enabled */
#define	IEEE80211_F_PBAR	0x04000000	/* CONF: PBAC required */
#define	IEEE80211_F_BGSCAN	0x08000000	/* STATUS: background scan */
#define IEEE80211_F_AUTO_JOIN	0x10000000	/* CONF: auto-join active */
#define	IEEE80211_F_VHTON	0x20000000	/* CONF: VHT enabled */
#define IEEE80211_F_DISABLE_BG_AUTO_CONNECT 0x40000000  /* CONF: disable auto connect to wifi when doing backgound scan */
#define IEEE80211_F_HEON    0x80000000  /* CONF: HE enabled */

/* ic_xflags */
#define	IEEE80211_F_TX_MGMT_ONLY 0x00000001	/* leave data frames on ifq */

/* ic_caps */
#define	IEEE80211_C_WEP		0x00000001	/* CAPABILITY: WEP available */
#define	IEEE80211_C_IBSS	0x00000002	/* CAPABILITY: IBSS available */
#define	IEEE80211_C_PMGT	0x00000004	/* CAPABILITY: Power mgmt */
#define	IEEE80211_C_HOSTAP	0x00000008	/* CAPABILITY: HOSTAP avail */
#define	IEEE80211_C_AHDEMO	0x00000010	/* CAPABILITY: Old Adhoc Demo */
#define	IEEE80211_C_APPMGT	0x00000020	/* CAPABILITY: AP power mgmt */
#define	IEEE80211_C_TXPMGT	0x00000040	/* CAPABILITY: tx power mgmt */
#define	IEEE80211_C_SHSLOT	0x00000080	/* CAPABILITY: short slottime */
#define	IEEE80211_C_SHPREAMBLE	0x00000100	/* CAPABILITY: short preamble */
#define	IEEE80211_C_MONITOR	0x00000200	/* CAPABILITY: monitor mode */
#define IEEE80211_C_SCANALL	0x00000400	/* CAPABILITY: scan all chan */
#define IEEE80211_C_QOS		0x00000800	/* CAPABILITY: QoS avail */
#define IEEE80211_C_RSN		0x00001000	/* CAPABILITY: RSN avail */
#define IEEE80211_C_MFP		0x00002000	/* CAPABILITY: MFP avail */
#define IEEE80211_C_RAWCTL	0x00004000	/* CAPABILITY: raw ctl */
#define IEEE80211_C_SCANALLBAND	0x00008000	/* CAPABILITY: scan all bands */
#define IEEE80211_C_TX_AMPDU	0x00010000	/* CAPABILITY: send A-MPDU */
#define IEEE80211_C_AMSDU_IN_AMPDU 0x00020000 /* CAPABILITY: Rx AMSDU inside AMPDU */
#define IEEE80211_C_TX_AMPDU_SETUP_IN_HW 0x00040000 /* CAPABILITY: BA negotiation in HW */
#define IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW 0x00080000  /* CAPABILITY: for 160mhz */
#define IEEE80211_C_TX_AMPDU_SETUP_IN_RS 0x00100000

/* flags for ieee80211_fix_rate() */
#define	IEEE80211_F_DOSORT	0x00000001	/* sort rate list */
#define	IEEE80211_F_DOFRATE	0x00000002	/* use fixed rate */
#define	IEEE80211_F_DONEGO	0x00000004	/* calc negotiated rate */
#define	IEEE80211_F_DODEL	0x00000008	/* delete ignore rate */

#define IEEE80211_EVT_STA_ASSOC_DONE            1
#define IEEE80211_EVT_STA_DEAUTH                2
#define IEEE80211_EVT_COUNTRY_CODE_UPDATE       3
#define IEEE80211_EVT_SCAN_DONE                 4

void	ieee80211_ifattach(struct _ifnet *, IOEthernetController *controller);
void	ieee80211_ifdetach(struct _ifnet *);
void	ieee80211_channel_init(struct _ifnet *);
void	ieee80211_media_init(struct _ifnet *);
int	ieee80211_media_change(struct _ifnet *);
void	ieee80211_media_status(struct _ifnet *, struct ifmediareq *);
int	ieee80211_ioctl(struct _ifnet *, u_long, caddr_t);
int	ieee80211_get_rate(struct ieee80211com *);
void	ieee80211_watchdog(struct _ifnet *);
int	ieee80211_fix_rate(struct ieee80211com *, struct ieee80211_node *, int);
uint64_t	ieee80211_rate2media(struct ieee80211com *, int,
		    enum ieee80211_phymode);
int	ieee80211_media2rate(uint64_t);
uint64_t	ieee80211_mcs2media(struct ieee80211com *, int,
		    enum ieee80211_phymode);
int	ieee80211_media2mcs(uint64_t);
u_int8_t ieee80211_rate2plcp(u_int8_t, enum ieee80211_phymode);
u_int8_t ieee80211_plcp2rate(u_int8_t, enum ieee80211_phymode);
u_int	ieee80211_mhz2ieee(u_int, u_int);
u_int	ieee80211_chan2ieee(struct ieee80211com *,
		const struct ieee80211_channel *);
u_int	ieee80211_ieee2mhz(u_int, u_int);
int	ieee80211_min_basic_rate(struct ieee80211com *);
int	ieee80211_max_basic_rate(struct ieee80211com *);
int	ieee80211_setmode(struct ieee80211com *, enum ieee80211_phymode);
enum ieee80211_phymode ieee80211_next_mode(struct _ifnet *);
enum ieee80211_phymode ieee80211_chan2mode(struct ieee80211com *,
		const struct ieee80211_channel *);
void	ieee80211_disable_wep(struct ieee80211com *); 
void	ieee80211_disable_rsn(struct ieee80211com *); 
int	ieee80211_add_ess(struct ieee80211com *, struct ieee80211_join *);
void	ieee80211_del_ess(struct ieee80211com *, char *, int, int);
void	ieee80211_set_ess(struct ieee80211com *, struct ieee80211_ess *,
	    struct ieee80211_node *);
void    ieee80211_deselect_ess(struct ieee80211com *);
struct ieee80211_ess *ieee80211_get_ess(struct ieee80211com *, const char *, int);
void ieee80211_begin_cache_bgscan(struct _ifnet *);

extern	int ieee80211_cache_size;

#endif /* _NET80211_IEEE80211_VAR_H_ */
