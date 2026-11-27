/*	$OpenBSD$	*/

/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/systm.h>

#include <crypto/i31.h>

void
br_i31_decode(uint32_t *x, const void *src, size_t len)
{
	const unsigned char *buf;
	size_t u, v;
	uint32_t acc;
	int acc_len;

	buf = static_cast<const unsigned char *>(src);
	u = len;
	v = 1;
	acc = 0;
	acc_len = 0;
	while (u -- > 0) {
		uint32_t b;

		b = buf[u];
		acc |= (b << acc_len);
		acc_len += 8;
		if (acc_len >= 31) {
			x[v ++] = acc & (uint32_t)0x7FFFFFFF;
			acc_len -= 31;
			acc = b >> (8 - acc_len);
		}
	}
	if (acc_len != 0) {
		x[v ++] = acc;
	}
	x[0] = br_i31_bit_length(x + 1, v - 1);
}

static inline void
br_enc32be(void *dst, uint32_t x)
{
	unsigned char *buf;

	buf = static_cast<unsigned char *>(dst);
	buf[0] = (unsigned char)(x >> 24);
	buf[1] = (unsigned char)(x >> 16);
	buf[2] = (unsigned char)(x >> 8);
	buf[3] = (unsigned char)x;
}

void
br_i31_encode(void *dst, size_t len, const uint32_t *x)
{
	unsigned char *buf;
	size_t k, xlen;
	uint32_t acc;
	int acc_len;

	xlen = (x[0] + 31) >> 5;
	if (xlen == 0) {
		memset(dst, 0, len);
		return;
	}
	buf = static_cast<unsigned char *>(dst) + len;
	k = 1;
	acc = 0;
	acc_len = 0;
	while (len != 0) {
		uint32_t w;

		w = (k <= xlen) ? x[k] : 0;
		k ++;
		if (acc_len == 0) {
			acc = w;
			acc_len = 31;
		} else {
			uint32_t z;

			z = acc | (w << acc_len);
			acc_len --;
			acc = w >> (31 - acc_len);
			if (len >= 4) {
				buf -= 4;
				len -= 4;
				br_enc32be(buf, z);
			} else {
				switch (len) {
				case 3:
					buf[-3] = (unsigned char)(z >> 16);
					/* fall through */
				case 2:
					buf[-2] = (unsigned char)(z >> 8);
					/* fall through */
				case 1:
					buf[-1] = (unsigned char)z;
					break;
				}
				return;
			}
		}
	}
}

uint32_t
br_i31_iszero(const uint32_t *x)
{
	uint32_t z;
	size_t u;

	z = 0;
	for (u = (x[0] + 31) >> 5; u > 0; u --) {
		z |= x[u];
	}
	return ~(z | -z) >> 31;
}

uint32_t
br_i31_add(uint32_t *a, const uint32_t *b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 63) >> 5;
	for (u = 1; u < m; u ++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw + bw + cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & (uint32_t)0x7FFFFFFF, aw);
	}
	return cc;
}

uint32_t
br_i31_sub(uint32_t *a, const uint32_t *b, uint32_t ctl)
{
	uint32_t cc;
	size_t u, m;

	cc = 0;
	m = (a[0] + 63) >> 5;
	for (u = 1; u < m; u ++) {
		uint32_t aw, bw, naw;

		aw = a[u];
		bw = b[u];
		naw = aw - bw - cc;
		cc = naw >> 31;
		a[u] = MUX(ctl, naw & 0x7FFFFFFF, aw);
	}
	return cc;
}

void
br_i31_reduce(uint32_t *x, const uint32_t *a, const uint32_t *m)
{
	uint32_t m_bitlen, a_bitlen;
	size_t mlen, alen, u;

	m_bitlen = m[0];
	mlen = (m_bitlen + 31) >> 5;

	x[0] = m_bitlen;
	if (m_bitlen == 0) {
		return;
	}

	/*
	 * If the source is shorter, then simply copy all words from a[]
	 * and zero out the upper words.
	 */
	a_bitlen = a[0];
	alen = (a_bitlen + 31) >> 5;
	if (a_bitlen < m_bitlen) {
		memcpy(x + 1, a + 1, alen * sizeof *a);
		for (u = alen; u < mlen; u ++) {
			x[u + 1] = 0;
		}
		return;
	}

	/*
	 * The source length is at least equal to that of the modulus.
	 * We must thus copy N-1 words, and input the remaining words
	 * one by one.
	 */
	memcpy(x + 1, a + 2 + (alen - mlen), (mlen - 1) * sizeof *a);
	x[mlen] = 0;
	for (u = 1 + alen - mlen; u > 0; u --) {
		br_i31_muladd_small(x, a[u], m);
	}
}

/*
 * Compute the bit length of a 32-bit integer. Returned value is between 0
 * and 32 (inclusive).
 */
static inline uint32_t
BIT_LENGTH(uint32_t x)
{
	uint32_t k, c;

	k = NEQ(x, 0);
	c = GT(x, 0xFFFF); x = MUX(c, x >> 16, x); k += c << 4;
	c = GT(x, 0x00FF); x = MUX(c, x >>  8, x); k += c << 3;
	c = GT(x, 0x000F); x = MUX(c, x >>  4, x); k += c << 2;
	c = GT(x, 0x0003); x = MUX(c, x >>  2, x); k += c << 1;
	k += GT(x, 0x0001);
	return k;
}

uint32_t
br_i31_bit_length(uint32_t *x, size_t xlen)
{
	uint32_t tw, twk;

	tw = 0;
	twk = 0;
	while (xlen -- > 0) {
		uint32_t w, c;

		c = EQ(tw, 0);
		w = x[xlen];
		tw = MUX(c, w, tw);
		twk = MUX(c, (uint32_t)xlen, twk);
	}
	return (twk << 5) + BIT_LENGTH(tw);
}

/*
 * Constant-time division. The dividend hi:lo is divided by the
 * divisor d; the quotient is returned and the remainder is written
 * in *r. If hi == d, then the quotient does not fit on 32 bits;
 * returned value is thus truncated. If hi > d, returned values are
 * indeterminate.
 */
static uint32_t
br_divrem(uint32_t hi, uint32_t lo, uint32_t d, uint32_t *r)
{
	/* TODO: optimize this */
	uint32_t q;
	uint32_t ch, cf;
	int k;

	q = 0;
	ch = EQ(hi, d);
	hi = MUX(ch, 0, hi);
	for (k = 31; k > 0; k --) {
		int j;
		uint32_t w, ctl, hi2, lo2;

		j = 32 - k;
		w = (hi << j) | (lo >> k);
		ctl = GE(w, d) | (hi >> k);
		hi2 = (w - d) >> j;
		lo2 = lo - (d << k);
		hi = MUX(ctl, hi2, hi);
		lo = MUX(ctl, lo2, lo);
		q |= ctl << k;
	}
	cf = GE(lo, d) | hi;
	q |= cf;
	*r = MUX(cf, lo - d, lo);
	return q;
}

/*
 * Wrapper for br_divrem(); the remainder is returned, and the quotient
 * is discarded.
 */
static inline uint32_t
br_rem(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	br_divrem(hi, lo, d, &r);
	return r;
}

/*
 * Wrapper for br_divrem(); the quotient is returned, and the remainder
 * is discarded.
 */
static inline uint32_t
br_div(uint32_t hi, uint32_t lo, uint32_t d)
{
	uint32_t r;

	return br_divrem(hi, lo, d, &r);
}

/*
 * Multiply two 31-bit integers, with a 62-bit result. This default
 * implementation assumes that the basic multiplication operator
 * yields constant-time code.
 */
#define MUL31(x, y)     ((uint64_t)(x) * (uint64_t)(y))

void
br_i31_muladd_small(uint32_t *x, uint32_t z, const uint32_t *m)
{
	uint32_t m_bitlen;
	unsigned mblr;
	size_t u, mlen;
	uint32_t a0, a1, b0, hi, g, q, tb;
	uint32_t under, over;
	uint32_t cc;

	/*
	 * We can test on the modulus bit length since we accept to
	 * leak that length.
	 */
	m_bitlen = m[0];
	if (m_bitlen == 0) {
		return;
	}
	if (m_bitlen <= 31) {
		uint32_t lo;

		hi = x[1] >> 1;
		lo = (x[1] << 31) | z;
		x[1] = br_rem(hi, lo, m[1]);
		return;
	}
	mlen = (m_bitlen + 31) >> 5;
	mblr = (unsigned)m_bitlen & 31;

	/*
	 * Principle: we estimate the quotient (x*2^31+z)/m by
	 * doing a 64/32 division with the high words.
	 *
	 * Let:
	 *   w = 2^31
	 *   a = (w*a0 + a1) * w^N + a2
	 *   b = b0 * w^N + b2
	 * such that:
	 *   0 <= a0 < w
	 *   0 <= a1 < w
	 *   0 <= a2 < w^N
	 *   w/2 <= b0 < w
	 *   0 <= b2 < w^N
	 *   a < w*b
	 * I.e. the two top words of a are a0:a1, the top word of b is
	 * b0, we ensured that b0 is "full" (high bit set), and a is
	 * such that the quotient q = a/b fits on one word (0 <= q < w).
	 *
	 * If a = b*q + r (with 0 <= r < q), we can estimate q by
	 * doing an Euclidean division on the top words:
	 *   a0*w+a1 = b0*u + v  (with 0 <= v < b0)
	 * Then the following holds:
	 *   0 <= u <= w
	 *   u-2 <= q <= u
	 */
	hi = x[mlen];
	if (mblr == 0) {
		a0 = x[mlen];
		memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
		x[1] = z;
		a1 = x[mlen];
		b0 = m[mlen];
	} else {
		a0 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
		memmove(x + 2, x + 1, (mlen - 1) * sizeof *x);
		x[1] = z;
		a1 = ((x[mlen] << (31 - mblr)) | (x[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
		b0 = ((m[mlen] << (31 - mblr)) | (m[mlen - 1] >> mblr))
			& 0x7FFFFFFF;
	}

	/*
	 * We estimate a divisor q. If the quotient returned by br_div()
	 * is g:
	 * -- If a0 == b0 then g == 0; we want q = 0x7FFFFFFF.
	 * -- Otherwise:
	 *    -- if g == 0 then we set q = 0;
	 *    -- otherwise, we set q = g - 1.
	 * The properties described above then ensure that the true
	 * quotient is q-1, q or q+1.
	 *
	 * Take care that a0, a1 and b0 are 31-bit words, not 32-bit. We
	 * must adjust the parameters to br_div() accordingly.
	 */
	g = br_div(a0 >> 1, a1 | (a0 << 31), b0);
	q = MUX(EQ(a0, b0), 0x7FFFFFFF, MUX(EQ(g, 0), 0, g - 1));

	/*
	 * We subtract q*m from x (with the extra high word of value 'hi').
	 * Since q may be off by 1 (in either direction), we may have to
	 * add or subtract m afterwards.
	 *
	 * The 'tb' flag will be true (1) at the end of the loop if the
	 * result is greater than or equal to the modulus (not counting
	 * 'hi' or the carry).
	 */
	cc = 0;
	tb = 1;
	for (u = 1; u <= mlen; u ++) {
		uint32_t mw, zw, xw, nxw;
		uint64_t zl;

		mw = m[u];
		zl = MUL31(mw, q) + cc;
		cc = (uint32_t)(zl >> 31);
		zw = (uint32_t)zl & (uint32_t)0x7FFFFFFF;
		xw = x[u];
		nxw = xw - zw;
		cc += nxw >> 31;
		nxw &= 0x7FFFFFFF;
		x[u] = nxw;
		tb = MUX(EQ(nxw, mw), tb, GT(nxw, mw));
	}

	/*
	 * If we underestimated q, then either cc < hi (one extra bit
	 * beyond the top array word), or cc == hi and tb is true (no
	 * extra bit, but the result is not lower than the modulus). In
	 * these cases we must subtract m once.
	 *
	 * Otherwise, we may have overestimated, which will show as
	 * cc > hi (thus a negative result). Correction is adding m once.
	 */
	over = GT(cc, hi);
	under = ~over & (tb | LT(cc, hi));
	br_i31_add(x, m, over);
	br_i31_sub(x, m, under);
}

int
br_i31_decode_cmp(const void *src, size_t len, const uint32_t *m)
{
	const unsigned char *buf;
	size_t mlen, tlen, u, v;
	uint32_t r, acc;
	int acc_len;

	buf = static_cast<const unsigned char *>(src);
	mlen = (m[0] + 31) >> 5;
	tlen = (mlen << 2);
	if (tlen < len) {
		tlen = len;
	}
	tlen += 4;
	r = 0;

	v = 1;
	acc = 0;
	acc_len = 0;

	for (u = 0; u < tlen; u ++) {
		uint32_t b;

		if (u < len) {
			b = buf[len - 1 - u];
		} else {
			b = 0;
		}
		acc |= (b << acc_len);
		acc_len += 8;
		if (acc_len >= 31) {
			uint32_t xw;

			xw = acc & (uint32_t)0x7FFFFFFF;
			acc_len -= 31;
			acc = b >> (8 - acc_len);
			if (v <= mlen) {
				uint32_t cc;

				cc = (uint32_t)CMP(xw, m[v]);
				r = MUX(EQ(cc, 0), r, cc);
			} else {
				r = MUX(EQ(xw, 0), r, 1);
			}
			v ++;
		}
	}

	/*
	 * 'r' contains the comparison result:
	 *  0x00000000   value is equal to m
	 *  0x00000001   value is greater than m
	 *  0xFFFFFFFF   value is lower than m
	 */
	if (r == 0xFFFFFFFF)
		return -1;
	else
		return r;
}
