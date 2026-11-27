/*	$OpenBSD$	*/

/*
 * Copyright (c) 2026 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/mbuf.h>
#include <sys/endian.h>
#include <sys/types.h>

#include <net/if.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_crypto.h>
#include <net80211/ieee80211_priv.h>

#include <crypto/i31.h>
#include <crypto/ec_p256_m31.h>

#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>

#define SAE_P256_PRIME_LEN	IEEE80211_SAE_MAX_ECC_PRIME_LEN

/*
 * Expected number of 4-byte words in an i31 integer array.
 * There is one 4-byte length word, followed by enough data
 * words to store the group's prime number.
 */
 #define SAE_I31INT_WORDS (1 + (SAE_P256_PRIME_LEN / 4) + 1)
#define SAE_I31INT_BITS (((SAE_P256_PRIME_LEN * 8 / 31) << 5) + \
    (SAE_P256_PRIME_LEN * 8 % 31))
#define SAE_I31SUM_BITS (SAE_I31INT_BITS + 1)

/* Derive the P-256 password token (PT) used by H2E from password and SSID. */
int
ieee80211_sae_password_to_pt(uint8_t *pt, const uint8_t *password,
	size_t password_len, const uint8_t *ssid, size_t ssid_len)
{
	static const uint8_t info1[] = "SAE Hash to Element u1 P1";
	static const uint8_t info2[] = "SAE Hash to Element u2 P2";
	const br_ec_impl *group = &br_ec_p256_m31;
	HMAC_SHA256_CTX ctx;
	uint8_t seed[SHA256_DIGEST_LENGTH];
	uint8_t value1[48], value2[48], one[SAE_P256_PRIME_LEN] = {0};
	uint8_t point1[1 + SAE_P256_PRIME_LEN * 2];
	uint8_t point2[1 + SAE_P256_PRIME_LEN * 2];
	int ret = -1;

	if (pt == NULL || password == NULL || password_len == 0 ||
	    password_len > 63 || ssid == NULL || ssid_len == 0 || ssid_len > 32)
		return -1;

	/* pwd-seed = HKDF-Extract(ssid, password). */
	HMAC_SHA256_Init(&ctx, ssid, ssid_len);
	HMAC_SHA256_Update(&ctx, password, password_len);
	HMAC_SHA256_Final(seed, &ctx);

	/* First 48 bytes of HKDF-Expand(PRK, info) use counters 1 and 2. */
	uint8_t counter = 1;
	uint8_t block[SHA256_DIGEST_LENGTH];
	HMAC_SHA256_Init(&ctx, seed, sizeof(seed));
	HMAC_SHA256_Update(&ctx, info1, sizeof(info1) - 1);
	HMAC_SHA256_Update(&ctx, &counter, sizeof(counter));
	HMAC_SHA256_Final(block, &ctx);
	memcpy(value1, block, sizeof(block));
	counter = 2;
	HMAC_SHA256_Init(&ctx, seed, sizeof(seed));
	HMAC_SHA256_Update(&ctx, block, sizeof(block));
	HMAC_SHA256_Update(&ctx, info1, sizeof(info1) - 1);
	HMAC_SHA256_Update(&ctx, &counter, sizeof(counter));
	HMAC_SHA256_Final(block, &ctx);
	memcpy(value1 + sizeof(block), block, sizeof(value1) - sizeof(block));

	counter = 1;
	HMAC_SHA256_Init(&ctx, seed, sizeof(seed));
	HMAC_SHA256_Update(&ctx, info2, sizeof(info2) - 1);
	HMAC_SHA256_Update(&ctx, &counter, sizeof(counter));
	HMAC_SHA256_Final(block, &ctx);
	memcpy(value2, block, sizeof(block));
	counter = 2;
	HMAC_SHA256_Init(&ctx, seed, sizeof(seed));
	HMAC_SHA256_Update(&ctx, block, sizeof(block));
	HMAC_SHA256_Update(&ctx, info2, sizeof(info2) - 1);
	HMAC_SHA256_Update(&ctx, &counter, sizeof(counter));
	HMAC_SHA256_Final(block, &ctx);
	memcpy(value2 + sizeof(block), block, sizeof(value2) - sizeof(block));

	if (!br_ec_p256_sswu(point1, value1, sizeof(value1)) ||
	    !br_ec_p256_sswu(point2, value2, sizeof(value2)))
		goto done;
	one[sizeof(one) - 1] = 1;
	if (!group->muladd(point1, point2, sizeof(point1), one, sizeof(one),
	    one, sizeof(one), BR_EC_secp192r1))
		goto done;
	memcpy(pt, point1 + 1, SAE_P256_PRIME_LEN * 2);
	ret = 0;
done:
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(seed, sizeof(seed));
	explicit_bzero(value1, sizeof(value1));
	explicit_bzero(value2, sizeof(value2));
	explicit_bzero(one, sizeof(one));
	explicit_bzero(block, sizeof(block));
	explicit_bzero(point1, sizeof(point1));
	explicit_bzero(point2, sizeof(point2));
	return ret;
}

static inline void
pwe_hash(const uint8_t *salt, size_t salt_len,
    const uint8_t *addr_max, const uint8_t *addr_min, uint8_t *hash)
{
	HMAC_SHA256_CTX ctx;

	HMAC_SHA256_Init(&ctx, salt, salt_len);

	HMAC_SHA256_Update(&ctx, addr_max, IEEE80211_ADDR_LEN);
	HMAC_SHA256_Update(&ctx, addr_min, IEEE80211_ADDR_LEN);

	HMAC_SHA256_Final(hash, &ctx);
}

/* Derive the SAE password element (PWE) from PT and two MAC addresses. */
int
ieee80211_sae_derive_password_elem(uint8_t *pwe, const uint8_t *pt,
    const uint8_t *own_macaddr, const uint8_t *bssid)
{
	const uint8_t *addr_max, *addr_min;
	uint8_t salt[SAE_P256_PRIME_LEN];
	uint8_t hash[SAE_P256_PRIME_LEN];
	uint8_t bin[SAE_P256_PRIME_LEN];
	const unsigned char *generator, *order;
	size_t xoff, prime_len, generator_len, order_len;
	const br_ec_impl *group = &br_ec_p256_m31;
	int curve = BR_EC_secp192r1; /* Group 19, P-256 */
	uint32_t one[SAE_I31INT_WORDS];
	uint32_t val[SAE_I31INT_WORDS];
	uint32_t r[SAE_I31INT_WORDS];
	uint32_t t[SAE_I31INT_WORDS];
	unsigned char point[1 + SAE_P256_PRIME_LEN * 2];

	generator = group->generator(curve, &generator_len);
	order = group->order(curve, &order_len);
	xoff = group->xoff(curve, &prime_len);
	DPRINTF(("%s: xoff=%zu prime_len=%zu\n", __func__, xoff, prime_len));

	if (prime_len != SAE_P256_PRIME_LEN)
		return -1;

	memset(salt, 0, sizeof(salt));
	memset(hash, 0, sizeof(hash));

	if (memcmp(own_macaddr, bssid, IEEE80211_ADDR_LEN) > 0) {
		addr_max = own_macaddr;
		addr_min = bssid;
	} else {
		addr_max = bssid;
		addr_min = own_macaddr;
	}

	/*
	 * val = H(0^n, MAX(STA-A-MAC,STA-B-MAC) || MIN(STA-A-MAC,STA-B-MAC))
	 */
	pwe_hash(salt, sizeof(salt), addr_max, addr_min, hash);

	/* val as i31 integer. */
	br_i31_decode(val, hash, sizeof(hash));
	val[0] = SAE_I31INT_BITS;

	/* The number 1 as i31 integer. */
	br_i31_zero(one, SAE_I31INT_BITS);
	one[1] = 0x1;
	br_i31_encode(bin, sizeof(bin), one);

	/* The order ("r") of the group as i31 integer. */
	br_i31_decode(r, order, order_len);

	/* val = val modulo (r - 1) + 1 */
	br_i31_sub(r, one, 1); /* r - 1 */
	br_i31_reduce(t, val, r); /* val modulo (r - 1) */
	br_i31_add(t, one, 1); /* + 1 */
	memcpy(val, t, sizeof(val)); /* val = t */

	br_i31_encode(bin, sizeof(bin), val);

	/* represent PT as a curve point */
	point[0] = 0x04; /* "uncompressed" format (RFC 5480, 2.2) */
	memcpy(&point[1], pt, SAE_P256_PRIME_LEN);
	memcpy(&point[SAE_P256_PRIME_LEN + 1], pt + SAE_P256_PRIME_LEN,
	    SAE_P256_PRIME_LEN);

	/* PWE = scalar-op(val, PT) */
	if (!group->mul(point, sizeof(point), bin, prime_len, curve))
		return -1;

	memcpy(pwe, &point[1], SAE_P256_PRIME_LEN * 2);

	return 0;
}

int
ieee80211_sae_derive_commit_elem(uint8_t *scalar, uint8_t *element_x,
    uint8_t *element_y, uint8_t *sae_rand, const uint8_t *pwe)
{
	const br_ec_impl *group = &br_ec_p256_m31;
	int curve = BR_EC_secp192r1; /* Group 19, P-256 */
	const unsigned char *order;
	unsigned char prime[1 + SAE_P256_PRIME_LEN];
	uint32_t one[SAE_I31INT_WORDS];
	uint32_t r[SAE_I31INT_WORDS];
	uint32_t rand[SAE_I31INT_WORDS];
	uint32_t mask[SAE_I31INT_WORDS];
	uint32_t t[SAE_I31INT_WORDS];
	uint32_t val[SAE_I31INT_WORDS];
	uint32_t p[SAE_I31INT_WORDS];
	size_t xoff, prime_len, order_len;
	int ret = -1, tries;
	unsigned char point[1 + SAE_P256_PRIME_LEN * 2];
	uint8_t bin[SAE_P256_PRIME_LEN];

	order = group->order(curve, &order_len);
	xoff = group->xoff(curve, &prime_len);
	DPRINTF(("%s: xoff=%zu prime_len=%zu\n", __func__, xoff, prime_len));

	if (prime_len != SAE_P256_PRIME_LEN) {
		DPRINTF(("%s: wrong prime length %zu\n", __func__, prime_len));
		goto done;
	}

	if (group->prime(curve, prime, sizeof(prime)) == 0) {
		DPRINTF(("%s: no prime\n", __func__));
		goto done;
	}

	/* The group's prime number as an i31 integer. */
	br_i31_decode(p, prime, prime_len);

	/* The number 1 as i31 integer. */
	br_i31_zero(one, SAE_I31INT_BITS);
	one[1] = 0x1;
	br_i31_encode(bin, sizeof(bin), one);

	/* The order ("r") of the group as i31 integer. */
	br_i31_decode(r, order, order_len);
	DPRINTF(("order_len=%zu\n", order_len));
	DPRINTF(("r bit length=%u\n", r[0]));

	/* Choose a random value 'rand' such that: 1 < rand < r */
	for (tries = 0; tries < 100; tries++) {
		arc4random_buf(bin, sizeof(bin));
		br_i31_decode(rand, bin, sizeof(bin));
		rand[0] = SAE_I31INT_BITS;
		explicit_bzero(bin, sizeof(bin));

		if (br_i31_iszero(rand))
			continue;

		br_i31_encode(bin, sizeof(bin), rand);

		/* Ensure that rand < r holds. */
		memcpy(t, r, sizeof(t)); /* t = r */
		br_i31_encode(bin, sizeof(bin), t);
		DPRINTF(("t bit length=%u\n", t[0]));
		DPRINTF(("one bit length=%u\n", one[0]));
		br_i31_sub(t, one, 1); /* t = r - 1 */
		br_i31_encode(bin, sizeof(bin), t);
		br_i31_reduce(val, rand, t); /* val = rand modulo (r - 1) */
		br_i31_encode(bin, sizeof(bin), val);
		memcpy(rand, val, sizeof(rand)); /* rand = val */

		/* Ensure that 1 < rand holds. */
		memcpy(t, rand, sizeof(t)); /* t = rand */
		br_i31_sub(t, one, 1);   /* t = rand - 1 */
		if (br_i31_iszero(rand) || br_i31_iszero(t))
			continue; /* --> rand <= 1 */

		break;
	}
	if (tries >= 100) /* should not happen */
		goto done;

	br_i31_encode(sae_rand, SAE_P256_PRIME_LEN, rand);

	/*
	 * Choose a random value 'mask' such that:
	 * 1 < mask < r && ((rand + mask) % r) > 1
	 */
	for (tries = 0; tries < 100; tries++) {
		arc4random_buf(bin, sizeof(bin));
		br_i31_decode(mask, bin, sizeof(bin));
		mask[0] = SAE_I31INT_BITS;
		explicit_bzero(bin, sizeof(bin));

		if (br_i31_iszero(mask))
			continue;

		/* Ensure that mask < r holds. */
		memcpy(t, r, sizeof(t)); /* t = r */
		br_i31_sub(t, one, 1); /* t = r - 1 */
		br_i31_reduce(val, mask, t); /* val = mask modulo (r - 1) */
		memcpy(mask, val, sizeof(mask)); /* mask = val */

		/* Ensure that 1 < mask holds. */
		memcpy(t, mask, sizeof(t)); /* t = mask */
		br_i31_sub(t, one, 1);   /* t = mask - 1 */
		if (br_i31_iszero(mask) || br_i31_iszero(t))
			continue; /* --> mask <= 1 */

		rand[0] = mask[0] = SAE_I31SUM_BITS;
		memcpy(t, rand, sizeof(t)); /* t = rand */
		br_i31_add(t, mask, 1); /* t = rand + mask */
		rand[0] = mask[0] = SAE_I31INT_BITS;
		br_i31_reduce(val, t, r); /* val = ((rand + mask) % r) */
		if (br_i31_iszero(val))
			continue; /* --> scalar == 0 */

		memcpy(t, val, sizeof(t)); /* t = val */
		br_i31_sub(t, one, 1);   /* t = val - 1 */
		if (br_i31_iszero(t))
			continue; /* --> ((rand + mask) % r) == 1 */
		break;
	}
	if (tries >= 100) /* should not happen */
		goto done;

	br_i31_encode(scalar, SAE_P256_PRIME_LEN, val);

	br_i31_encode(bin, sizeof(bin), mask);

	/* represent PWE as a curve point */
	point[0] = 0x04; /* "uncompressed" format (RFC 5480, 2.2) */
	memcpy(&point[1], pwe, SAE_P256_PRIME_LEN);
	memcpy(&point[SAE_P256_PRIME_LEN + 1], pwe + SAE_P256_PRIME_LEN,
	    SAE_P256_PRIME_LEN);

	/* point = scalar-op(mask, PWE) */
	if (!group->mul(point, sizeof(point), bin, prime_len, curve))
		goto done;

	/* inverse-op(point(X, Y)) -> point(X, p - Y) */
	if (!group->invert(curve, point, sizeof(point)))
		goto done;

	/* COMMIT-ELEMENT = inverse-op(scalar-op(mask, PWE)) */
	memcpy(element_x, &point[1], SAE_P256_PRIME_LEN);
	memcpy(element_y, &point[1 + SAE_P256_PRIME_LEN], SAE_P256_PRIME_LEN);

	ret = 0;
done:
	explicit_bzero(prime, sizeof(prime));
	explicit_bzero(one, sizeof(one));
	explicit_bzero(r, sizeof(r));
	explicit_bzero(rand, sizeof(rand));
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(t, sizeof(t));
	explicit_bzero(val, sizeof(val));
	explicit_bzero(p, sizeof(p));
	explicit_bzero(point, sizeof(point));
	explicit_bzero(bin, sizeof(bin));
	if (ret != 0)
		DPRINTF(("%s: error %d\n", __func__, ret));
	return ret;
}

uint16_t
ieee80211_sae_verify_commit_elem(const uint8_t **scalar,
    const uint8_t **element_x, const uint8_t **element_y,
    const uint8_t *frm, size_t remain, const unsigned char *own_scalar,
     const unsigned char *own_element_x, const unsigned char *own_element_y)
{
	const br_ec_impl *group = &br_ec_p256_m31;
	int curve = BR_EC_secp192r1; /* Group 19, P-256 */
	const unsigned char *order;
	uint32_t one[SAE_I31INT_WORDS];
	uint32_t r[SAE_I31INT_WORDS];
	size_t xoff, prime_len, order_len;
	uint16_t fc_group;
	unsigned char point[1 + SAE_P256_PRIME_LEN * 2];
	uint8_t bin[SAE_P256_PRIME_LEN];
	uint16_t ret = IEEE80211_STATUS_UNSPECIFIED;

	*scalar = NULL;
	*element_x = NULL;
	*element_y = NULL;

	/*
	 * Optional elements may follow the fixed part; H2E peers commonly send
	 * rejected-groups or token-container elements there. Parse what is
	 * fixed and ignore the rest, as the reference implementation does
	 * (it only hexdumps whatever trails the element).
	 */
	if (remain < IEEE80211_SAE_COMMIT_MIN_LEN)
		goto done;

	fc_group = LE_READ_2(frm);
	if (fc_group != curve) {
		ret = IEEE80211_STATUS_BAD_FC_GROUP;
		goto done;
	}
	frm += 2;

	*scalar = frm;
	frm += SAE_P256_PRIME_LEN;

	*element_x = frm;
	frm += SAE_P256_PRIME_LEN;

	*element_y = frm;
	frm += SAE_P256_PRIME_LEN;

	order = group->order(curve, &order_len);
	xoff = group->xoff(curve, &prime_len);
	if (prime_len != SAE_P256_PRIME_LEN)
		goto done;

	/* The order ("r") of the group as i31 integer. */
	br_i31_decode(r, order, order_len);

	/* The number 1 as i31 integer. */
	br_i31_zero(one, SAE_I31INT_BITS);
	one[1] = 0x1;
	br_i31_encode(bin, sizeof(bin), one);

	/* Represent the peer's element as a curve point. */
	point[0] = 0x04; /* "uncompressed" format (RFC 5480, 2.2) */
	memcpy(&point[1], *element_x, prime_len);
	memcpy(&point[prime_len + 1], *element_y, prime_len);

	ret = IEEE80211_STATUS_SUCCESS;

	/* Ensure our own scalar or element weren't replayed to us. */
	ret |= !!(timingsafe_bcmp(own_scalar, *scalar, prime_len) == 0 ||
	    timingsafe_bcmp(own_element_x, *element_x, prime_len) == 0 ||
	    timingsafe_bcmp(own_element_y, *element_y, prime_len) == 0);

	/* Ensure that 1 < scalar < r holds. */
	ret |= !!(br_i31_decode_cmp(*scalar, prime_len, one) != 1 ||
	    br_i31_decode_cmp(*scalar, prime_len, r) != -1);

	/* Ensure that the provided group element is valid. */
	ret |= !!(group->mul(point, sizeof(point), bin, prime_len, curve) == 0);

	_KASSERT(ret == IEEE80211_STATUS_SUCCESS /* 0x0 */ ||
	    ret == IEEE80211_STATUS_UNSPECIFIED /* 0x1 */);
	done:
	explicit_bzero(one, sizeof(one));
	explicit_bzero(r, sizeof(r));
	explicit_bzero(point, sizeof(point));
	explicit_bzero(bin, sizeof(bin));

	return ret;
}

uint16_t
ieee80211_sae_derive_shared_secret(uint8_t *k, const uint8_t *scalar,
    const uint8_t *element_x, const uint8_t *element_y, const uint8_t *pwe,
    const uint8_t *rand)
{
	const br_ec_impl *group = &br_ec_p256_m31;
	int curve = BR_EC_secp192r1; /* Group 19, P-256 */
	const unsigned char *order;
	size_t xoff, prime_len, order_len;
	unsigned char pointA[1 + SAE_P256_PRIME_LEN * 2];
	unsigned char pointB[1 + SAE_P256_PRIME_LEN * 2];
	uint8_t one_bin[SAE_P256_PRIME_LEN];
	uint32_t one[SAE_I31INT_WORDS];
	uint32_t t[SAE_I31INT_WORDS];
	uint16_t ret = IEEE80211_STATUS_UNSPECIFIED;

	order = group->order(curve, &order_len);
	xoff = group->xoff(curve, &prime_len);
	if (prime_len != SAE_P256_PRIME_LEN)
		goto done;

	/* The number 1 as i31 integer. */
	br_i31_zero(one, SAE_I31INT_BITS);
	one[1] = 0x1;

	/* The number 1 in unsigned big-endian. */
	br_i31_encode(one_bin, sizeof(one_bin), one);

	/*
	 * K = scalar-op(rand,
	 *               (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                        PEER-COMMIT-ELEMENT)))
	 */

	/* represent PWE as a curve point */
	pointA[0] = 0x04; /* "uncompressed" format (RFC 5480, 2.2) */
	memcpy(&pointA[1], pwe, prime_len * 2);

	ret = IEEE80211_STATUS_SUCCESS;

	/* pointA = scalar-op(peer-commit-scalar, PWE) */
	ret |= !!(group->mul(pointA, sizeof(pointA), scalar, prime_len,
	    curve) == 0);

	/* Represent the peer's element as a curve point. */
	pointB[0] = 0x04; /* "uncompressed" format (RFC 5480, 2.2) */
	memcpy(&pointB[1], element_x, prime_len);
	memcpy(&pointB[prime_len + 1], element_y, prime_len);

	/* pointA = (elem-op(pointA, PEER-COMMIT-ELEMENT)) */
	ret |= !!(group->muladd(pointA, pointB, sizeof(pointA),
	    one_bin, sizeof(one_bin), one_bin, sizeof(one_bin), curve) == 0);

	/* K = pointA = scalar-op(rand, pointA) */
	ret |= !!(group->mul(pointA, sizeof(pointA), rand, prime_len,
	    curve) == 0);

	/* K must not be the identity element (point-at-infinity) */
	br_i31_decode(t, pointA, 1 + SAE_P256_PRIME_LEN);
	ret |= !!br_i31_iszero(t);
	br_i31_decode(t, &pointA[1 + SAE_P256_PRIME_LEN], SAE_P256_PRIME_LEN);
	ret |= !!br_i31_iszero(t);

	/* k = F(K) -> X coordinate */
	memcpy(k, &pointA[1], SAE_P256_PRIME_LEN);

	_KASSERT(ret == IEEE80211_STATUS_SUCCESS /* 0x0 */ ||
	    ret == IEEE80211_STATUS_UNSPECIFIED /* 0x1 */);

	done:
	explicit_bzero(pointA, sizeof(pointA));
	explicit_bzero(pointB, sizeof(pointB));
	explicit_bzero(one_bin, sizeof(one_bin));
	explicit_bzero(one, sizeof(one));
	explicit_bzero(t, sizeof(t));
	return ret;
}

int
ieee80211_sae_derive_secret_keys(uint8_t *sae_kck, uint8_t *pmk,
	uint8_t *pmkid, const uint8_t *k, const uint8_t *own_scalar,
	const uint8_t *peer_scalar)
{
	const br_ec_impl *group = &br_ec_p256_m31;
	int curve = BR_EC_secp192r1; /* Group 19, P-256 */
	const unsigned char *order;
	size_t xoff, prime_len, order_len;
	uint32_t r[SAE_I31INT_WORDS];
	uint32_t os[SAE_I31INT_WORDS];
	uint32_t ps[SAE_I31INT_WORDS];
	uint32_t context[SAE_I31INT_WORDS];
	uint32_t t[SAE_I31INT_WORDS];
	uint8_t salt[SHA256_DIGEST_LENGTH];
	uint8_t keyseed[SHA256_DIGEST_LENGTH];
	uint8_t bin[SAE_P256_PRIME_LEN];
	uint8_t keys[SHA256_DIGEST_LENGTH + IEEE80211_PMK_LEN];
	HMAC_SHA256_CTX ctx;
	int ret = -1;

	order = group->order(curve, &order_len);
	xoff = group->xoff(curve, &prime_len);
	if (prime_len != SAE_P256_PRIME_LEN)
		goto done;

	/* The order ("r") of the group as i31 integer. */
	br_i31_decode(r, order, order_len);

	/* Own SAE commit scalar as i31 integer. */
	br_i31_decode(os, own_scalar, SAE_P256_PRIME_LEN);
	os[0] = SAE_I31SUM_BITS;

	/* Peer SAE commit scalar as i31 integer. */
	br_i31_decode(ps, peer_scalar, SAE_P256_PRIME_LEN);
	ps[0] = SAE_I31SUM_BITS;

	/* context = (commit-scalar + peer-commit-scalar) mod r */
	memcpy(t, os, sizeof(t)); /* t = commit-scalar */
	br_i31_add(t, ps, 1); /* t = commit-scalar + peer-scalar */
	br_i31_reduce(context, t, r); /* context = t modulo r */

	br_i31_encode(bin, order_len, context);
	memcpy(pmkid, bin, IEEE80211_PMKID_LEN);

	/*
	 * The salt value is either a list of rejected groups or zero.
	 * We only support mandatory group 19, which cannot be rejected.
	 */
	memset(salt, 0, sizeof(salt));

	/* keyseed = H(salt, k) */
	HMAC_SHA256_Init(&ctx, salt, sizeof(salt));
	HMAC_SHA256_Update(&ctx, k, SAE_P256_PRIME_LEN);
	HMAC_SHA256_Final(keyseed, &ctx);

	/* SAE-KCK and PMK = KDF(keyseed, "SAE KCK and PMK", context) */
	ieee80211_kdf(keyseed, sizeof(keyseed),
	    (const u_int8_t *)"SAE KCK and PMK", 15 /* KDF omits \0 */,
	    bin, order_len, keys, sizeof(keys));

	memcpy(sae_kck, &keys[0], SHA256_DIGEST_LENGTH);
	memcpy(pmk,  &keys[SHA256_DIGEST_LENGTH], IEEE80211_PMK_LEN);
	ret = 0;
	done:
	explicit_bzero(r, sizeof(r));
	explicit_bzero(os, sizeof(os));
	explicit_bzero(ps, sizeof(ps));
	explicit_bzero(context, sizeof(context));
	explicit_bzero(t, sizeof(t));
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(keyseed, sizeof(keyseed));
	explicit_bzero(bin, sizeof(bin));
	explicit_bzero(keys, sizeof(keys));
	explicit_bzero(&ctx, sizeof(ctx));

	return ret;
}

int
ieee80211_sae_verify_confirm(const uint8_t *frm, size_t remain,
    const uint8_t *kck, const uint8_t *own_scalar,
    const uint8_t *own_element_x, const uint8_t *own_element_y,
    const uint8_t *peer_scalar,
    const uint8_t *peer_element_x, const uint8_t *peer_element_y)
{
	HMAC_SHA256_CTX ctx;
	u_int8_t digest[SHA256_DIGEST_LENGTH];
	const uint8_t *verifier;

	/*
	 * confirm = CN(SAE-KCK, peer-send-confirm, peer-commit-scalar,
	 *	peer-commit-element, commit-scalar, commit-element)
	 */
	HMAC_SHA256_Init(&ctx, kck, SHA256_DIGEST_LENGTH);

	HMAC_SHA256_Update(&ctx, frm, 2); /* peer-send-confirm */

	HMAC_SHA256_Update(&ctx, peer_scalar,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);
	HMAC_SHA256_Update(&ctx, peer_element_x,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);
	HMAC_SHA256_Update(&ctx, peer_element_y,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);

	HMAC_SHA256_Update(&ctx, own_scalar,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);
	HMAC_SHA256_Update(&ctx, own_element_x,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);
	HMAC_SHA256_Update(&ctx, own_element_y,
	    IEEE80211_SAE_MAX_ECC_PRIME_LEN);

	HMAC_SHA256_Final(digest, &ctx);

	verifier = frm + 2;

	int ret = timingsafe_bcmp(verifier, digest, SHA256_DIGEST_LENGTH) == 0 ?
	    0 : -1;
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(digest, sizeof(digest));
	return ret;
}
