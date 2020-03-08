/*	$OpenBSD: sha1.h,v 1.6 2014/11/16 17:39:09 tedu Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include "types.h"

#define SHA1_MAC_LEN 20

#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20

typedef struct {
	u_int32_t	state[5];
	u_int64_t	count;
	unsigned char	buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

void SHA1Init(SHA1_CTX * context);
void SHA1Transform(u_int32_t state[5], const unsigned char buffer[SHA1_BLOCK_LENGTH]);
void SHA1Update(SHA1_CTX *context, const void *data, unsigned int len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
             const u8 *addr[], const size_t *len, u8 *mac);
int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
           u8 *mac);
int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
                int iterations, u8 *buf, size_t buflen);
#endif /* _SHA1_H_ */
