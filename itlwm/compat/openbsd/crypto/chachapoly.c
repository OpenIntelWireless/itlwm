/*
 * Copyright (c) 2015 Mike Belopuhov
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

#include <crypto/chacha_private.h>
#include <crypto/poly1305.h>
#include <crypto/chachapoly.h>

int
chacha20_setkey(void *sched, u_int8_t *key, int len)
{
	struct chacha20_ctx *ctx = (struct chacha20_ctx *)sched;

	if (len != CHACHA20_KEYSIZE + CHACHA20_SALT)
		return (-1);

	/* initial counter is 1 */
	ctx->nonce[0] = 1;
	memcpy(ctx->nonce + CHACHA20_CTR, key + CHACHA20_KEYSIZE,
	    CHACHA20_SALT);
	chacha_keysetup((chacha_ctx *)&ctx->block, key, CHACHA20_KEYSIZE * 8);
	return (0);
}

void
chacha20_reinit(caddr_t key, u_int8_t *iv)
{
	struct chacha20_ctx *ctx = (struct chacha20_ctx *)key;

	chacha_ivsetup((chacha_ctx *)ctx->block, iv, ctx->nonce);
}

void
chacha20_crypt(caddr_t key, u_int8_t *data)
{
	struct chacha20_ctx *ctx = (struct chacha20_ctx *)key;

	chacha_encrypt_bytes((chacha_ctx *)ctx->block, data, data,
	    CHACHA20_BLOCK_LEN);
}

void
Chacha20_Poly1305_Init(void *xctx)
{
	CHACHA20_POLY1305_CTX *ctx = (CHACHA20_POLY1305_CTX *)xctx;

	memset(ctx, 0, sizeof(*ctx));
}

void
Chacha20_Poly1305_Setkey(void *xctx, const uint8_t *key, uint16_t klen)
{
	CHACHA20_POLY1305_CTX *ctx = (CHACHA20_POLY1305_CTX *)xctx;

	/* salt is provided with the key material */
	memcpy(ctx->nonce + CHACHA20_CTR, key + CHACHA20_KEYSIZE,
	    CHACHA20_SALT);
	chacha_keysetup((chacha_ctx *)&ctx->chacha, key, CHACHA20_KEYSIZE * 8);
}

void
Chacha20_Poly1305_Reinit(void *xctx, const uint8_t *iv, uint16_t ivlen)
{
	CHACHA20_POLY1305_CTX *ctx = (CHACHA20_POLY1305_CTX *)xctx;

	/* initial counter is 0 */
	chacha_ivsetup((chacha_ctx *)&ctx->chacha, iv, ctx->nonce);
	chacha_encrypt_bytes((chacha_ctx *)&ctx->chacha, ctx->key, ctx->key,
	    POLY1305_KEYLEN);
	poly1305_init((poly1305_state *)&ctx->poly, ctx->key);
}

int
Chacha20_Poly1305_Update(void *xctx, const uint8_t *data, uint16_t len)
{
    static const char zeroes[POLY1305_BLOCK_LEN] = {0};
	CHACHA20_POLY1305_CTX *ctx = (CHACHA20_POLY1305_CTX *)xctx;
	size_t rem;

	poly1305_update((poly1305_state *)&ctx->poly, data, len);

	/* number of bytes in the last 16 byte block */
	rem = (len + POLY1305_BLOCK_LEN) & (POLY1305_BLOCK_LEN - 1);
	if (rem > 0)
		poly1305_update((poly1305_state *)&ctx->poly, (const unsigned char *)zeroes,
		    (size_t)(POLY1305_BLOCK_LEN - rem));
	return (0);
}

void
Chacha20_Poly1305_Final(uint8_t tag[POLY1305_TAGLEN], void *xctx)
{
	CHACHA20_POLY1305_CTX *ctx = (CHACHA20_POLY1305_CTX *)xctx;

	poly1305_finish((poly1305_state *)&ctx->poly, tag);
	memset(ctx, 0, sizeof(*ctx));
}
