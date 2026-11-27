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

/** \file bearssl_ec.h
 *
 * # Elliptic Curves
 *
 * This file documents the EC implementations provided with BearSSL.
 *
 * ## Elliptic Curve API
 *
 * Only "named curves" are supported. Each EC implementation supports
 * one or several named curves, identified by symbolic identifiers.
 * These identifiers are small integers, that correspond to the values
 * registered by the
 * [IANA](http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
 *
 * Since all currently defined elliptic curve identifiers are in the 0..31
 * range, it is convenient to encode support of some curves in a 32-bit
 * word, such that bit x corresponds to curve of identifier x.
 *
 * An EC implementation is incarnated by a `br_ec_impl` instance, that
 * offers the following fields:
 *
 *   - `supported_curves`
 *
 *      A 32-bit word that documents the identifiers of the curves supported
 *      by this implementation.
 *
 *   - `generator()`
 *
 *      Callback method that returns a pointer to the conventional generator
 *      point for that curve.
 *
 *   - `order()`
 *
 *      Callback method that returns a pointer to the subgroup order for
 *      that curve. That value uses unsigned big-endian encoding.
 *
 *   - `xoff()`
 *
 *      Callback method that returns the offset and length of the X
 *      coordinate in an encoded point.
 *
 *   - `prime()`
 *
 *      Callback method that returns the curve's prime number.
 *      (This is an API extension added by OpenBSD for use with net80211/SAE.)

 *   - `invert()`
 *
 *      Invert a curve point.
 *      (This is an API extension added by OpenBSD for use with net80211/SAE.)
 *
 *   - `mul()`
 *
 *      Multiply a curve point with an integer.
 *
 *   - `mulgen()`
 *
 *      Multiply the curve generator with an integer. This may be faster
 *      than the generic `mul()`.
 *
 *   - `muladd()`
 *
 *      Multiply two curve points by two integers, and return the sum of
 *      the two products.
 *
 * All curve points are represented in uncompressed format. The `mul()`
 * and `muladd()` methods take care to validate that the provided points
 * are really part of the relevant curve subgroup.
 *
 * For all point multiplication functions, the following holds:
 *
 *   - Functions validate that the provided points are valid members
 *     of the relevant curve subgroup. An error is reported if that is
 *     not the case.
 *
 *   - Processing is constant-time, even if the point operands are not
 *     valid. This holds for both the source and resulting points, and
 *     the multipliers (integers). Only the byte length of the provided
 *     multiplier arrays (not their actual value length in bits) may
 *     leak through timing-based side channels.
 *
 *   - The multipliers (integers) MUST be lower than the subgroup order.
 *     If this property is not met, then the result is indeterminate,
 *     but an error value is not necessarily returned.
 */

/*
 * Standard curve ID. These ID are equal to the assigned numerical
 * identifiers assigned to these curves for TLS:
 *    http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */

/** \brief Identifier for named curve secp192r1. */
#define BR_EC_secp192r1          19

/**
 * \brief Type for an EC implementation.
 */
typedef struct {
	/**
	 * \brief Supported curves.
	 *
	 * This word is a bitfield: bit `x` is set if the curve of ID `x`
	 * is supported. E.g. an implementation supporting both NIST P-256
	 * (secp256r1, ID 23) and NIST P-384 (secp384r1, ID 24) will have
	 * value `0x01800000` in this field.
	 */
	uint32_t supported_curves;

	/**
	 * \brief Get the conventional generator.
	 *
	 * This function returns the conventional generator (encoded
	 * curve point) for the specified curve. This function MUST NOT
	 * be called if the curve is not supported.
	 *
	 * \param curve   curve identifier.
	 * \param len     receiver for the encoded generator length (in bytes).
	 * \return  the encoded generator.
	 */
	const unsigned char *(*generator)(int curve, size_t *len);

	/**
	 * \brief Get the subgroup order.
	 *
	 * This function returns the order of the subgroup generated by
	 * the conventional generator, for the specified curve. Unsigned
	 * big-endian encoding is used. This function MUST NOT be called
	 * if the curve is not supported.
	 *
	 * \param curve   curve identifier.
	 * \param len     receiver for the encoded order length (in bytes).
	 * \return  the encoded order.
	 */
	const unsigned char *(*order)(int curve, size_t *len);

	/**
	 * \brief Get the offset and length for the X coordinate.
	 *
	 * This function returns the offset and length (in bytes) of
	 * the X coordinate in an encoded non-zero point.
	 *
	 * \param curve   curve identifier.
	 * \param len     receiver for the X coordinate length (in bytes).
	 * \return  the offset for the X coordinate (in bytes).
	 */
	size_t (*xoff)(int curve, size_t *len);

	/**
	 * \brief Get the prime number of the curve as an integer in
	 * unsigned big-endian encoding.
	 * \param curve   curve identifier.
	 * \param p       output buffer
	 * \param plen    output buffer size; must be at least as large as
	 *		  offset + length as returned by xoff().
	 * \return  1 on success, 0 on error.
	 */
	int (*prime)(int curve, unsigned char *p, size_t plen);

	/**
	 * \brief Invert a curve point:
	 * The point's Y coordinate becomes equal to prime - Y.
	 *
	 * \param curve   curve identifier.
	 * \param G       point to invert.
	 * \param Glen    length of the encoded point (in bytes).
	 * \return  1 on success, 0 on error.
	 */
	int (*invert)(int curve, unsigned char *G, size_t Glen);

	/**
	 * \brief Multiply a curve point by an integer.
	 *
	 * The source point is provided in array `G` (of size `Glen` bytes);
	 * the multiplication result is written over it. The multiplier
	 * `x` (of size `xlen` bytes) uses unsigned big-endian encoding.
	 *
	 * Rules:
	 *
	 *   - The specified curve MUST be supported.
	 *
	 *   - The source point must be a valid point on the relevant curve
	 *     subgroup (and not the "point at infinity" either). If this is
	 *     not the case, then this function returns an error (0).
	 *
	 *   - The multiplier integer MUST be non-zero and less than the
	 *     curve subgroup order. If this property does not hold, then
	 *     the result is indeterminate and an error code is not
	 *     guaranteed.
	 *
	 * Returned value is 1 on success, 0 on error. On error, the
	 * contents of `G` are indeterminate.
	 *
	 * \param G       point to multiply.
	 * \param Glen    length of the encoded point (in bytes).
	 * \param x       multiplier (unsigned big-endian).
	 * \param xlen    multiplier length (in bytes).
	 * \param curve   curve identifier.
	 * \return  1 on success, 0 on error.
	 */
	uint32_t (*mul)(unsigned char *G, size_t Glen,
		const unsigned char *x, size_t xlen, int curve);

	/**
	 * \brief Multiply the generator by an integer.
	 *
	 * The multiplier MUST be non-zero and less than the curve
	 * subgroup order. Results are indeterminate if this property
	 * does not hold.
	 *
	 * \param R       output buffer for the point.
	 * \param x       multiplier (unsigned big-endian).
	 * \param xlen    multiplier length (in bytes).
	 * \param curve   curve identifier.
	 * \return  encoded result point length (in bytes).
	 */
	size_t (*mulgen)(unsigned char *R,
		const unsigned char *x, size_t xlen, int curve);

	/**
	 * \brief Multiply two points by two integers and add the
	 * results.
	 *
	 * The point `x*A + y*B` is computed and written back in the `A`
	 * array.
	 *
	 * Rules:
	 *
	 *   - The specified curve MUST be supported.
	 *
	 *   - The source points (`A` and `B`)  must be valid points on
	 *     the relevant curve subgroup (and not the "point at
	 *     infinity" either). If this is not the case, then this
	 *     function returns an error (0).
	 *
	 *   - If the `B` pointer is `NULL`, then the conventional
	 *     subgroup generator is used. With some implementations,
	 *     this may be faster than providing a pointer to the
	 *     generator.
	 *
	 *   - The multiplier integers (`x` and `y`) MUST be non-zero
	 *     and less than the curve subgroup order. If either integer
	 *     is zero, then an error is reported, but if one of them is
	 *     not lower than the subgroup order, then the result is
	 *     indeterminate and an error code is not guaranteed.
	 *
	 *   - If the final result is the point at infinity, then an
	 *     error is returned.
	 *
	 * Returned value is 1 on success, 0 on error. On error, the
	 * contents of `A` are indeterminate.
	 *
	 * \param A       first point to multiply.
	 * \param B       second point to multiply (`NULL` for the generator).
	 * \param len     common length of the encoded points (in bytes).
	 * \param x       multiplier for `A` (unsigned big-endian).
	 * \param xlen    length of multiplier for `A` (in bytes).
	 * \param y       multiplier for `A` (unsigned big-endian).
	 * \param ylen    length of multiplier for `A` (in bytes).
	 * \param curve   curve identifier.
	 * \return  1 on success, 0 on error.
	 */
	uint32_t (*muladd)(unsigned char *A, const unsigned char *B, size_t len,
		const unsigned char *x, size_t xlen,
		const unsigned char *y, size_t ylen, int curve);
} br_ec_impl;

/**
 * \brief EC implementation "m31" for P-256.
 *
 * This implementation uses specialised code for curve secp256r1 (also
 * known as NIST P-256), relying on multiplications of 31-bit values
 * (MUL31).
 */
extern const br_ec_impl br_ec_p256_m31;

/* Hash a 48-byte field element to a P-256 point using simplified SWU. */
int br_ec_p256_sswu(unsigned char *, const unsigned char *, size_t);
uint32_t br_ec_p256_hnp_point(unsigned char *, const unsigned char *, unsigned);
void br_ec_p256_ct_copy(uint32_t, void *, const void *, size_t);
