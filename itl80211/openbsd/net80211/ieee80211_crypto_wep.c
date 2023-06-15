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
/*	$OpenBSD: ieee80211_crypto_wep.c,v 1.17 2018/11/09 14:14:31 claudio Exp $	*/

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
 * This code implements Wired Equivalent Privacy (WEP) defined in
 * IEEE Std 802.11-2007 section 8.2.1.
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

#include <crypto/arc4.h>
#include <sys/_arc4random.h>

/* WEP software crypto context */
struct ieee80211_wep_ctx {
	struct rc4_ctx	rc4;
	u_int32_t	iv;
};

/*
 * Initialize software crypto context.  This function can be overridden
 * by drivers doing hardware crypto.
 */
int
ieee80211_wep_set_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
	struct ieee80211_wep_ctx *ctx;

	ctx = (struct ieee80211_wep_ctx *)malloc(sizeof(*ctx), 0, 0);
	if (ctx == NULL)
		return ENOMEM;
	k->k_priv = ctx;
	return 0;
}

void
ieee80211_wep_delete_key(struct ieee80211com *ic, struct ieee80211_key *k)
{
	if (k->k_priv != NULL) {
		explicit_bzero(k->k_priv, sizeof(struct ieee80211_wep_ctx));
		free(k->k_priv);
	}
	k->k_priv = NULL;
}

/* shortcut */
#define IEEE80211_WEP_HDRLEN	\
	(IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN)

mbuf_t
ieee80211_wep_encrypt(struct ieee80211com *ic, mbuf_t m0,
    struct ieee80211_key *k)
{
	struct ieee80211_wep_ctx *ctx = (struct ieee80211_wep_ctx *)k->k_priv;
	u_int8_t wepseed[16];
	const struct ieee80211_frame *wh;
	mbuf_t n0, m, n;
	u_int8_t *ivp, *icvp;
	u_int32_t iv, crc;
	int left, moff, noff, len, hdrlen;
    mbuf_t temp;

    mbuf_get(MBUF_DONTWAIT, mbuf_type(m0), &n0);
	if (n0 == NULL)
		goto nospace;
	if (m_dup_pkthdr(n0, m0, MBUF_DONTWAIT))
		goto nospace;
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) + IEEE80211_WEP_HDRLEN);
    mbuf_setlen(n0, mbuf_get_mhlen());
	if (mbuf_pkthdr_len(n0) >= mbuf_get_minclsize() - IEEE80211_WEP_CRCLEN) {
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

	/* select a new IV for every MPDU */
	iv = (ctx->iv != 0) ? ctx->iv : arc4random();
	/* skip weak IVs from Fluhrer/Mantin/Shamir */
	if (iv >= 0x03ff00 && (iv & 0xf8ff00) == 0x00ff00)
		iv += 0x000100;
	ctx->iv = iv + 1;
	ivp = mtod(n0, u_int8_t *) + hdrlen;
	ivp[0] = iv;
	ivp[1] = iv >> 8;
	ivp[2] = iv >> 16;
	ivp[3] = k->k_id << 6;

	/* compute WEP seed: concatenate IV and WEP Key */
	memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
	memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
	rc4_keysetup(&ctx->rc4, wepseed, IEEE80211_WEP_IVLEN + k->k_len);
	explicit_bzero(wepseed, sizeof(wepseed));

	/* encrypt frame body and compute WEP ICV */
	m = m0;
	n = n0;
	moff = hdrlen;
	noff = hdrlen + IEEE80211_WEP_HDRLEN;
	left = mbuf_pkthdr_len(m0)- moff;
	crc = ~0;
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
			if (left >= mbuf_get_minclsize() - IEEE80211_WEP_CRCLEN) {
                mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n), &n);
//				MCLGET(n, MBUF_DONTWAIT);
				if (mbuf_flags(n) & MBUF_EXT)
                    mbuf_setlen(n, MCLBYTES);
			}
			if (mbuf_len(n) > left)
                mbuf_setlen(n, left);
			noff = 0;
		}
		len = min(mbuf_len(m) - moff, mbuf_len(n) - noff);

		crc = ether_crc32_le_update(crc, mtod(m, const u_int8_t *) + moff, len);
		rc4_crypt(&ctx->rc4, mtod(m, u_char *) + moff,
		    mtod(n, u_char *) + noff, len);

		moff += len;
		noff += len;
		left -= len;
	}

	/* reserve trailing space for WEP ICV */
	if (mbuf_trailingspace(n) < IEEE80211_WEP_CRCLEN) {
        temp = NULL;
        mbuf_get(MBUF_DONTWAIT, mbuf_type(n), &temp);
		if (temp == NULL)
			goto nospace;
        mbuf_setnext(n, temp);
		n = mbuf_next(n);
        mbuf_setlen(n, 0);
	}

	/* finalize WEP ICV */
	icvp = mtod(n, uint8_t *) + mbuf_len(n);
	crc = ~crc;
	icvp[0] = crc;
	icvp[1] = crc >> 8;
	icvp[2] = crc >> 16;
	icvp[3] = crc >> 24;
	rc4_crypt(&ctx->rc4, icvp, icvp, IEEE80211_WEP_CRCLEN);
    mbuf_setlen(n, mbuf_len(n) + IEEE80211_WEP_CRCLEN);
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) + IEEE80211_WEP_CRCLEN);

	mbuf_freem(m0);
	return n0;
 nospace:
	ic->ic_stats.is_tx_nombuf++;
	mbuf_freem(m0);
	mbuf_freem(n0);
	return NULL;
}

mbuf_t
ieee80211_wep_decrypt(struct ieee80211com *ic, mbuf_t m0,
    struct ieee80211_key *k)
{
	struct ieee80211_wep_ctx *ctx = (struct ieee80211_wep_ctx *)k->k_priv;
	struct ieee80211_frame *wh;
	u_int8_t wepseed[16];
	u_int32_t crc, crc0;
	u_int8_t *ivp;
	mbuf_t n0, m, n;
	int hdrlen, left, moff, noff, len;
    mbuf_t temp;

	wh = mtod(m0, struct ieee80211_frame *);
	hdrlen = ieee80211_get_hdrlen(wh);

	if (mbuf_pkthdr_len(m0) < hdrlen + IEEE80211_WEP_TOTLEN) {
		mbuf_freem(m0);
		return NULL;
	}

	/* concatenate IV and WEP Key */
	ivp = (u_int8_t *)wh + hdrlen;
	memcpy(wepseed, ivp, IEEE80211_WEP_IVLEN);
	memcpy(wepseed + IEEE80211_WEP_IVLEN, k->k_key, k->k_len);
	rc4_keysetup((struct rc4_ctx *)&ctx->rc4, (u_char*)wepseed, (uint32_t)(IEEE80211_WEP_IVLEN + k->k_len));
	explicit_bzero(wepseed, sizeof(wepseed));

    mbuf_get(MBUF_DONTWAIT, mbuf_type(m0), &n0);
	if (n0 == NULL)
		goto nospace;
	if (m_dup_pkthdr(n0, m0, MBUF_DONTWAIT))
		goto nospace;
    mbuf_pkthdr_setlen(n0, mbuf_pkthdr_len(n0) - IEEE80211_WEP_TOTLEN);
	mbuf_setlen(n0, mbuf_get_mhlen());
	if (mbuf_pkthdr_len(n0) >= mbuf_get_minclsize()) {
        mbuf_mclget(MBUF_DONTWAIT, mbuf_type(n0), &n0);
//		MCLGET(n0, MBUF_DONTWAIT);
		if (mbuf_flags(n0) & MBUF_EXT)
            mbuf_setlen(n0, MCLBYTES);
//			n0->m_len = n0->m_ext.ext_size;
	}
	if (mbuf_len(n0) > mbuf_pkthdr_len(n0))
        mbuf_setlen(n0, mbuf_pkthdr_len(n0));

	/* copy 802.11 header and clear protected bit */
	memcpy(mtod(n0, caddr_t), wh, hdrlen);
	wh = mtod(n0, struct ieee80211_frame *);
	wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;

	/* decrypt frame body and compute WEP ICV */
	m = m0;
	n = n0;
	moff = hdrlen + IEEE80211_WEP_HDRLEN;
	noff = hdrlen;
	left = mbuf_pkthdr_len(n0) - noff;
	crc = ~0;
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

		rc4_crypt(&ctx->rc4, mtod(m, u_char*) + moff,
		    mtod(n, u_char*) + noff, len);
		crc = ether_crc32_le_update(crc, mtod(n, const u_int8_t *) + noff, len);

		moff += len;
		noff += len;
		left -= len;
	}

	/* decrypt ICV and compare it with calculated ICV */
	mbuf_copydata(m, moff, IEEE80211_WEP_CRCLEN, (caddr_t)&crc0);
	rc4_crypt(&ctx->rc4, (u_char*)&crc0, (u_char*)&crc0,
	    IEEE80211_WEP_CRCLEN);
	crc = ~crc;
	if (crc != letoh32(crc0)) {
		ic->ic_stats.is_rx_decryptcrc++;
		mbuf_freem(m0);
		mbuf_freem(n0);
		return NULL;
	}

	mbuf_freem(m0);
	return n0;
 nospace:
	ic->ic_stats.is_rx_nombuf++;
	mbuf_freem(m0);
	mbuf_freem(n0);
	return NULL;
}
