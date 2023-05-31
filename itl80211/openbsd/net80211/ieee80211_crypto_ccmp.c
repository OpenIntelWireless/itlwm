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
/*	$OpenBSD: ieee80211_crypto_ccmp.c,v 1.21 2018/11/09 14:14:31 claudio Exp $	*/

/*-
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
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

/*
 * This code implements the CTR with CBC-MAC protocol (CCMP) defined in
 * IEEE Std 802.11-2007 section 8.3.3.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_crypto.h>

#include <crypto/aes.h>

/* CCMP software crypto context */
struct ieee80211_ccmp_ctx {
	AES_CTX		aesctx;
};

/*
 * Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */
int
ieee80211_ccmp_set_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
	struct ieee80211_ccmp_ctx *ctx;

	ctx = (struct ieee80211_ccmp_ctx *)malloc(sizeof(*ctx), 0, 0);
	if (ctx == NULL)
		return ENOMEM;
	AES_Setkey(&ctx->aesctx, k->k_key, 16);
	k->k_priv = ctx;
	return 0;
}

void
ieee80211_ccmp_delete_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
	if (k->k_priv != NULL) {
		explicit_bzero(k->k_priv, sizeof(struct ieee80211_ccmp_ctx));
		free(k->k_priv);
	}
	k->k_priv = NULL;
}

/*-
 * Counter with CBC-MAC (CCM) - see RFC3610.
 * CCMP uses the following CCM parameters: M = 8, L = 2
 */
static void
ieee80211_ccmp_phase1(AES_CTX *ctx, const struct ieee80211_frame *wh,
    u_int64_t pn, int lm, u_int8_t b[16], u_int8_t a[16], u_int8_t s0[16])
{
	u_int8_t auth[32], nonce[13];
	u_int8_t *aad;
	u_int8_t tid = 0;
	int la, i;

	/* construct AAD (additional authenticated data) */
	aad = &auth[2];	/* skip l(a), will be filled later */
	*aad = wh->i_fc[0];
	/* 11w: conditionally mask subtype field */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA)
		*aad &= ~IEEE80211_FC0_SUBTYPE_MASK |
		   IEEE80211_FC0_SUBTYPE_QOS;
	aad++;
	/* protected bit is already set in wh */
	*aad = wh->i_fc[1];
	*aad &= ~(IEEE80211_FC1_RETRY | IEEE80211_FC1_PWR_MGT |
	    IEEE80211_FC1_MORE_DATA);
	/* 11n: conditionally mask order bit */
	if (ieee80211_has_qos(wh))
		*aad &= ~IEEE80211_FC1_ORDER;
	aad++;
	IEEE80211_ADDR_COPY(aad, wh->i_addr1); aad += IEEE80211_ADDR_LEN;
	IEEE80211_ADDR_COPY(aad, wh->i_addr2); aad += IEEE80211_ADDR_LEN;
	IEEE80211_ADDR_COPY(aad, wh->i_addr3); aad += IEEE80211_ADDR_LEN;
	*aad++ = wh->i_seq[0] & ~0xf0;
	*aad++ = 0;
	if (ieee80211_has_addr4(wh)) {
		IEEE80211_ADDR_COPY(aad,
		    ((const struct ieee80211_frame_addr4 *)wh)->i_addr4);
		aad += IEEE80211_ADDR_LEN;
	}
	if (ieee80211_has_qos(wh)) {
		/* 
		 * XXX 802.11-2012 11.4.3.3.3 g says the A-MSDU present bit
		 * must be set here if both STAs are SPP A-MSDU capable.
		 */
		*aad++ = tid = ieee80211_get_qos(wh) & IEEE80211_QOS_TID;
		*aad++ = 0;
	}

	/* construct CCM nonce */
	nonce[ 0] = tid;
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT)
		nonce[0] |= 1 << 4;	/* 11w: set management bit */
	IEEE80211_ADDR_COPY(&nonce[1], wh->i_addr2);
	nonce[ 7] = pn >> 40;	/* PN5 */
	nonce[ 8] = pn >> 32;	/* PN4 */
	nonce[ 9] = pn >> 24;	/* PN3 */
	nonce[10] = pn >> 16;	/* PN2 */
	nonce[11] = pn >> 8;	/* PN1 */
	nonce[12] = pn;		/* PN0 */

	/* add 2 authentication blocks (including l(a) and padded AAD) */
	la = aad - &auth[2];		/* fill l(a) */
	auth[0] = la >> 8;
	auth[1] = la & 0xff;
	memset(aad, 0, 30 - la);	/* pad AAD with zeros */

	/* construct first block B_0 */
	b[ 0] = 89;	/* Flags = 64*Adata + 8*((M-2)/2) + (L-1) */
	memcpy(&b[1], nonce, 13);
	b[14] = lm >> 8;
	b[15] = lm & 0xff;
	AES_Encrypt(ctx, b, b);

	for (i = 0; i < 16; i++)
		b[i] ^= auth[i];
	AES_Encrypt(ctx, b, b);
	for (i = 0; i < 16; i++)
		b[i] ^= auth[16 + i];
	AES_Encrypt(ctx, b, b);

	/* construct S_0 */
	a[ 0] = 1;	/* Flags = L' = (L-1) */
	memcpy(&a[1], nonce, 13);
	a[14] = a[15] = 0;
	AES_Encrypt(ctx, a, s0);
}

mbuf_t
ieee80211_ccmp_encrypt(struct ieee80211com *ic, mbuf_t m0,
    struct ieee80211_key *k)
{
	struct ieee80211_ccmp_ctx *ctx = (struct ieee80211_ccmp_ctx *)k->k_priv;
	const struct ieee80211_frame *wh;
	const u_int8_t *src;
	u_int8_t *ivp, *mic, *dst;
	u_int8_t a[16], b[16], s0[16], s[16];
	mbuf_t n0, m, n;
	int hdrlen, left, moff, noff, len;
	u_int16_t ctr;
	int i, j;
    mbuf_t temp;
    unsigned int max_chunks = 1;

    mbuf_get(MBUF_DONTWAIT, mbuf_type(m0), &n0);
	if (n0 == NULL)
		goto nospace;
	if (m_dup_pkthdr(n0, m0, MBUF_DONTWAIT))
		goto nospace;
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) + IEEE80211_CCMP_HDRLEN);
    mbuf_setlen(n0, mbuf_get_mhlen());
	if (mbuf_pkthdr_len(n0) >= mbuf_get_minclsize() - IEEE80211_CCMP_MICLEN) {
        mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n0), &n0);
		if (mbuf_flags(n0) & MBUF_EXT)
            mbuf_setlen(n0, MCLBYTES);
	}
	if (mbuf_len(n0) > mbuf_pkthdr_len(n0))
        mbuf_setlen(n0, mbuf_pkthdr_len(n0));

	/* copy 802.11 header */
	wh = mtod(m0, struct ieee80211_frame *);
	hdrlen = ieee80211_get_hdrlen(wh);
	memcpy(mtod(n0, caddr_t), wh, hdrlen);

	k->k_tsc++;	/* increment the 48-bit PN */

	/* construct CCMP header */
	ivp = mtod(n0, u_int8_t *) + hdrlen;
	ivp[0] = k->k_tsc;		/* PN0 */
	ivp[1] = k->k_tsc >> 8;		/* PN1 */
	ivp[2] = 0;			/* Rsvd */
	ivp[3] = k->k_id << 6 | IEEE80211_WEP_EXTIV;	/* KeyID | ExtIV */
	ivp[4] = k->k_tsc >> 16;	/* PN2 */
	ivp[5] = k->k_tsc >> 24;	/* PN3 */
	ivp[6] = k->k_tsc >> 32;	/* PN4 */
	ivp[7] = k->k_tsc >> 40;	/* PN5 */

	/* construct initial B, A and S_0 blocks */
	ieee80211_ccmp_phase1(&ctx->aesctx, wh, k->k_tsc,
	    mbuf_pkthdr_len(m0) - hdrlen, b, a, s0);

	/* construct S_1 */
	ctr = 1;
	a[14] = ctr >> 8;
	a[15] = ctr & 0xff;
	AES_Encrypt(&ctx->aesctx, a, s);

	/* encrypt frame body and compute MIC */
	j = 0;
	m = m0;
	n = n0;
	moff = hdrlen;
	noff = hdrlen + IEEE80211_CCMP_HDRLEN;
	left = mbuf_pkthdr_len(m0) - moff;
	while (left > 0) {
		if (moff == mbuf_len(m)) {
			/* nothing left to copy from m */
			m = mbuf_next(m);
			moff = 0;
		}
		if (noff == mbuf_len(n)) {
			/* n is full and there's more data to copy */
            temp = NULL;
            mbuf_get(MBUF_DONTWAIT, mbuf_type(n), &temp);
			if (temp == NULL)
				goto nospace;
            mbuf_setnext(n, temp);
			n = mbuf_next(n);
            mbuf_setlen(n, mbuf_get_mlen());
			if (left >= mbuf_get_minclsize() - IEEE80211_CCMP_MICLEN) {
                mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n), &n);
				if (mbuf_flags(n) & MBUF_EXT)
                    mbuf_setlen(n, MCLBYTES);
			}
			if (mbuf_len(n) > left)
                mbuf_setlen(n, left);
			noff = 0;
		}
		len = min(mbuf_len(m) - moff, mbuf_len(n) - noff);

		src = mtod(m, u_int8_t *) + moff;
		dst = mtod(n, u_int8_t *) + noff;
		for (i = 0; i < len; i++) {
			/* update MIC with clear text */
			b[j] ^= src[i];
			/* encrypt message */
			dst[i] = src[i] ^ s[j];
			if (++j < 16)
				continue;
			/* we have a full block, encrypt MIC */
			AES_Encrypt(&ctx->aesctx, b, b);
			/* construct a new S_ctr block */
			ctr++;
			a[14] = ctr >> 8;
			a[15] = ctr & 0xff;
			AES_Encrypt(&ctx->aesctx, a, s);
			j = 0;
		}

		moff += len;
		noff += len;
		left -= len;
	}
	if (j != 0)	/* partial block, encrypt MIC */
		AES_Encrypt(&ctx->aesctx, b, b);

	/* reserve trailing space for MIC */
	if (mbuf_trailingspace(n) < IEEE80211_CCMP_MICLEN) {
        temp = NULL;
        mbuf_get(MBUF_DONTWAIT, mbuf_type(n), &temp);
		if (temp == NULL)
			goto nospace;
        mbuf_setnext(n, temp);
		n = mbuf_next(n);
        mbuf_setlen(n, 0);
	}
	/* finalize MIC, U := T XOR first-M-bytes( S_0 ) */
	mic = mtod(n, u_int8_t *) + mbuf_len(n);
	for (i = 0; i < IEEE80211_CCMP_MICLEN; i++)
		mic[i] = b[i] ^ s0[i];
    mbuf_setlen(n, mbuf_len(n) + IEEE80211_CCMP_MICLEN);
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) + IEEE80211_CCMP_MICLEN);

	mbuf_freem(m0);
	return n0;
 nospace:
	ic->ic_stats.is_tx_nombuf++;
	mbuf_freem(m0);
	mbuf_freem(n0);
	return NULL;
}

int
ieee80211_ccmp_get_pn(uint64_t *pn, uint64_t **prsc, mbuf_t m,
    struct ieee80211_key *k)
{
   struct ieee80211_frame *wh;
   int hdrlen;
   const u_int8_t *ivp;

   wh = mtod(m, struct ieee80211_frame *);
   hdrlen = ieee80211_get_hdrlen(wh);
   if (mbuf_pkthdr_len(m) < hdrlen + IEEE80211_CCMP_HDRLEN)
       return EINVAL;

   ivp = (u_int8_t *)wh + hdrlen;

   /* check that ExtIV bit is set */
   if (!(ivp[3] & IEEE80211_WEP_EXTIV))
       return EINVAL;

   /* retrieve last seen packet number for this frame type/priority */
   if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
       IEEE80211_FC0_TYPE_DATA) {
       u_int8_t tid = ieee80211_has_qos(wh) ?
           ieee80211_get_qos(wh) & IEEE80211_QOS_TID : 0;
       *prsc = &k->k_rsc[tid];
   } else    /* 11w: management frames have their own counters */
       *prsc = &k->k_mgmt_rsc;

   /* extract the 48-bit PN from the CCMP header */
   *pn = (u_int64_t)ivp[0]      |
        (u_int64_t)ivp[1] <<  8 |
        (u_int64_t)ivp[4] << 16 |
        (u_int64_t)ivp[5] << 24 |
        (u_int64_t)ivp[6] << 32 |
        (u_int64_t)ivp[7] << 40;

   return 0;
}

mbuf_t
ieee80211_ccmp_decrypt(struct ieee80211com *ic, mbuf_t m0,
    struct ieee80211_key *k)
{
	struct ieee80211_ccmp_ctx *ctx = (struct ieee80211_ccmp_ctx *)k->k_priv;
	struct ieee80211_frame *wh;
	u_int64_t pn, *prsc;
    const u_int8_t *src;
	u_int8_t *dst;
	u_int8_t mic0[IEEE80211_CCMP_MICLEN];
	u_int8_t a[16], b[16], s0[16], s[16];
	mbuf_t n0, m, n;
	int hdrlen, left, moff, noff, len;
	u_int16_t ctr;
	int i, j;
    mbuf_t temp;
    unsigned int max_chunks = 1;

	wh = mtod(m0, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);
    if (mbuf_pkthdr_len(m0) < hdrlen + IEEE80211_CCMP_HDRLEN +
        IEEE80211_CCMP_MICLEN) {
        mbuf_freem(m0);
        return NULL;
    }
    
    /*
     * Get the frame's Packet Number (PN) and a pointer to our last-seen
     * Receive Sequence Counter (RSC) which we can use to detect replays.
     */
    if (ieee80211_ccmp_get_pn(&pn, &prsc, m0, k) != 0) {
        mbuf_freem(m0);
        return NULL;
    }

	if (pn <= *prsc) {
		/* replayed frame, discard */
		ic->ic_stats.is_ccmp_replays++;
		mbuf_freem(m0);
		return NULL;
	}

    mbuf_get(MBUF_DONTWAIT, mbuf_type(m0), &n0);
	if (n0 == NULL)
		goto nospace;
	if (m_dup_pkthdr(n0, m0, MBUF_DONTWAIT))
		goto nospace;
    
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) - (IEEE80211_CCMP_HDRLEN + IEEE80211_CCMP_MICLEN));
    mbuf_setlen(n0, mbuf_get_mhlen());
	if (mbuf_pkthdr_len(n0) >= mbuf_get_minclsize()) {
        mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n0), &n0);
		if (mbuf_flags(n0) & MBUF_EXT)
            mbuf_setlen(n0, MCLBYTES);
	}
	if (mbuf_len(n0) > mbuf_pkthdr_len(n0))
        mbuf_setlen(n0, mbuf_pkthdr_len(n0));

	/* construct initial B, A and S_0 blocks */
	ieee80211_ccmp_phase1(&ctx->aesctx, wh, pn,
	    mbuf_pkthdr_len(n0) - hdrlen, b, a, s0);

	/* copy 802.11 header and clear protected bit */
	memcpy(mtod(n0, caddr_t), wh, hdrlen);
	wh = mtod(n0, struct ieee80211_frame *);
	wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

	/* construct S_1 */
	ctr = 1;
	a[14] = ctr >> 8;
	a[15] = ctr & 0xff;
	AES_Encrypt(&ctx->aesctx, a, s);

	/* decrypt frame body and compute MIC */
	j = 0;
	m = m0;
	n = n0;
	moff = hdrlen + IEEE80211_CCMP_HDRLEN;
	noff = hdrlen;
	left = mbuf_pkthdr_len(n0) - noff;
	while (left > 0) {
		if (moff == mbuf_len(m)) {
			/* nothing left to copy from m */
			m = mbuf_next(m);
			moff = 0;
		}
		if (noff == mbuf_len(n)) {
			/* n is full and there's more data to copy */
            temp = NULL;
            mbuf_get(MBUF_DONTWAIT, mbuf_type(n), &temp);
			if (temp == NULL)
				goto nospace;
            mbuf_setnext(n, temp);
			n = mbuf_next(n);
            mbuf_setlen(n, mbuf_get_mlen());
			if (left >= mbuf_get_minclsize()) {
                mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n), &n);
				if (mbuf_flags(n) & MBUF_EXT)
                    mbuf_setlen(n, MCLBYTES);
			}
			if (mbuf_len(n) > left)
                mbuf_setlen(n, left);
			noff = 0;
		}
		len = min(mbuf_len(m) - moff, mbuf_len(n) - noff);

		src = mtod(m, u_int8_t *) + moff;
		dst = mtod(n, u_int8_t *) + noff;
		for (i = 0; i < len; i++) {
			/* decrypt message */
			dst[i] = src[i] ^ s[j];
			/* update MIC with clear text */
			b[j] ^= dst[i];
			if (++j < 16)
				continue;
			/* we have a full block, encrypt MIC */
			AES_Encrypt(&ctx->aesctx, b, b);
			/* construct a new S_ctr block */
			ctr++;
			a[14] = ctr >> 8;
			a[15] = ctr & 0xff;
			AES_Encrypt(&ctx->aesctx, a, s);
			j = 0;
		}

		moff += len;
		noff += len;
		left -= len;
	}
	if (j != 0)	/* partial block, encrypt MIC */
		AES_Encrypt(&ctx->aesctx, b, b);

	/* finalize MIC, U := T XOR first-M-bytes( S_0 ) */
	for (i = 0; i < IEEE80211_CCMP_MICLEN; i++)
		b[i] ^= s0[i];

	/* check that it matches the MIC in received frame */
	mbuf_copydata(m, moff, IEEE80211_CCMP_MICLEN, mic0);
	if (timingsafe_bcmp(mic0, b, IEEE80211_CCMP_MICLEN) != 0) {
		ic->ic_stats.is_ccmp_dec_errs++;
		mbuf_freem(m0);
		mbuf_freem(n0);
		return NULL;
	}

	/* update last seen packet number (MIC is validated) */
	*prsc = pn;

	mbuf_freem(m0);
	return n0;
 nospace:
	ic->ic_stats.is_rx_nombuf++;
	mbuf_freem(m0);
	mbuf_freem(n0);
	return NULL;
}
