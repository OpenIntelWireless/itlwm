/*
 * SHA1-based key derivation function (PBKDF2) for IEEE 802.11i
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "sha1.h"
#include "hmac.h"

static int openssl_hmac_vector(const u8 *key,
                   size_t key_len, size_t num_elem,
                   const u8 *addr[], const size_t *len, u8 *mac,
                   unsigned int mdlen)
{
    HMAC_SHA1_CTX ctx;
    size_t i;
    u_int8_t digest[SHA1_DIGEST_LENGTH];

    HMAC_SHA1_Init(&ctx, key, key_len);

    for (i = 0; i < num_elem; i++)
        HMAC_SHA1_Update(&ctx, addr[i], len[i]);

    HMAC_SHA1_Final(digest, &ctx);
    memcpy(mac, digest, sizeof(digest));

    return 0;
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
             const u8 *addr[], const size_t *len, u8 *mac)
{
    return openssl_hmac_vector(key, key_len, num_elem, addr,
                   len, mac, 20);
}


int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
           u8 *mac)
{
    return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}

static int pbkdf2_sha1_f(const char *passphrase, const u8 *ssid,
			 size_t ssid_len, int iterations, unsigned int count,
			 u8 *digest)
{
	unsigned char tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	const u8 *addr[2];
	size_t len[2];
	size_t passphrase_len = strlen(passphrase);

	addr[0] = ssid;
	len[0] = ssid_len;
	addr[1] = count_buf;
	len[1] = 4;

	/* F(P, S, c, i) = U1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 */

	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8) & 0xff;
	count_buf[3] = count & 0xff;
	if (hmac_sha1_vector((u8 *) passphrase, passphrase_len, 2, addr, len,
			     tmp))
		return -1;
	memcpy(digest, tmp, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		if (hmac_sha1((u8 *) passphrase, passphrase_len, tmp,
			      SHA1_MAC_LEN, tmp2))
			return -1;
		memcpy(tmp, tmp2, SHA1_MAC_LEN);
		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}

	return 0;
}


/**
 * pbkdf2_sha1 - SHA1-based key derivation function (PBKDF2) for IEEE 802.11i
 * @passphrase: ASCII passphrase
 * @ssid: SSID
 * @ssid_len: SSID length in bytes
 * @iterations: Number of iterations to run
 * @buf: Buffer for the generated key
 * @buflen: Length of the buffer in bytes
 * Returns: 0 on success, -1 of failure
 *
 * This function is used to derive PSK for WPA-PSK. For this protocol,
 * iterations is set to 4096 and buflen to 32. This function is described in
 * IEEE Std 802.11-2004, Clause H.4. The main construction is from PKCS#5 v2.0.
 */
int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
		int iterations, u8 *buf, size_t buflen)
{
	unsigned int count = 0;
	unsigned char *pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[SHA1_MAC_LEN];

	while (left > 0) {
		count++;
		if (pbkdf2_sha1_f(passphrase, ssid, ssid_len, iterations,
				  count, digest))
			return -1;
		plen = left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}

	return 0;
}
