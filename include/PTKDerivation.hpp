// PTK derivation inputs (802.11-2020 12.7.1.3).
#ifndef PTK_DERIVATION_HPP
#define PTK_DERIVATION_HPP

typedef void (*PTKKdf)(const uint8_t *key, size_t key_len,
    const uint8_t *label, size_t label_len,
    const uint8_t *context, size_t context_len,
    uint8_t *output, size_t output_len);

namespace PTKDerivation {

static const size_t kAddrLen = 6;
static const size_t kNonceLen = 32;
static const size_t kPmkLen = 32;
static const size_t kCcmpPtkLen = 48;

inline void
derive(int sha256, const uint8_t *pmk, const uint8_t *aa, const uint8_t *spa,
    const uint8_t *anonce, const uint8_t *snonce, uint8_t *ptk,
    size_t ptk_len, PTKKdf kdf, PTKKdf prf)
{
    uint8_t buf[2 * kAddrLen + 2 * kNonceLen];
    int ret;

    for (size_t i = 0; i < ptk_len; ++i)
        ptk[i] = 0;

    /* Min(AA,SPA) || Max(AA,SPA) */
    ret = memcmp(aa, spa, kAddrLen) < 0;
    memcpy(&buf[0], ret ? aa : spa, kAddrLen);
    memcpy(&buf[kAddrLen], ret ? spa : aa, kAddrLen);

    /* Min(ANonce,SNonce) || Max(ANonce,SNonce) */
    ret = memcmp(anonce, snonce, kNonceLen) < 0;
    memcpy(&buf[2 * kAddrLen], ret ? anonce : snonce, kNonceLen);
    memcpy(&buf[2 * kAddrLen + kNonceLen], ret ? snonce : anonce,
        kNonceLen);

    if (sha256) {
        kdf(pmk, kPmkLen, (const uint8_t *)"Pairwise key expansion", 22,
            buf, sizeof(buf), ptk, ptk_len < kCcmpPtkLen ? ptk_len : kCcmpPtkLen);
    } else {
        prf(pmk, kPmkLen, (const uint8_t *)"Pairwise key expansion", 23,
            buf, sizeof(buf), ptk, ptk_len);
    }
}

}

#endif
