//
//  endian.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _SYS_ENDIAN_H_
#define _SYS_ENDIAN_H_

#include <sys/cdefs.h>
#include <sys/_endian.h>
#include <sys/_types.h>

#define __FROM_SYS__ENDIAN
#include <machine/endian.h>
#undef __FROM_SYS__ENDIAN

#define _KERNEL
#define _LITTLE_ENDIAN    1234
#define _BIG_ENDIAN    4321
#define _PDP_ENDIAN    3412

//ZXY DEFINE
#define _BYTE_ORDER _LITTLE_ENDIAN

/* Note that these macros evaluate their arguments several times.  */

#define __swap16gen(x)                            \
    (__uint16_t)(((__uint16_t)(x) & 0xffU) << 8 | ((__uint16_t)(x) & 0xff00U) >> 8)

#define __swap32gen(x)                            \
    (__uint32_t)(((__uint32_t)(x) & 0xff) << 24 |            \
    ((__uint32_t)(x) & 0xff00) << 8 | ((__uint32_t)(x) & 0xff0000) >> 8 |\
    ((__uint32_t)(x) & 0xff000000) >> 24)

#define __swap64gen(x)                            \
    (__uint64_t)((((__uint64_t)(x) & 0xff) << 56) |            \
        ((__uint64_t)(x) & 0xff00ULL) << 40 |            \
        ((__uint64_t)(x) & 0xff0000ULL) << 24 |            \
        ((__uint64_t)(x) & 0xff000000ULL) << 8 |            \
        ((__uint64_t)(x) & 0xff00000000ULL) >> 8 |            \
        ((__uint64_t)(x) & 0xff0000000000ULL) >> 24 |        \
        ((__uint64_t)(x) & 0xff000000000000ULL) >> 40 |        \
        ((__uint64_t)(x) & 0xff00000000000000ULL) >> 56)

static __inline __uint16_t
__swap16md(__uint16_t x)
{
    return (__swap16gen(x));
}

static __inline __uint32_t
__swap32md(__uint32_t x)
{
    return (__swap32gen(x));
}

static __inline __uint64_t
__swap64md(__uint64_t x)
{
    return (__swap64gen(x));
}

#define __swap16(x)                            \
    (__uint16_t)(__builtin_constant_p(x) ? __swap16gen(x) : __swap16md(x))
#define __swap32(x)                            \
    (__uint32_t)(__builtin_constant_p(x) ? __swap32gen(x) : __swap32md(x))
#define __swap64(x)                            \
    (__uint64_t)(__builtin_constant_p(x) ? __swap64gen(x) : __swap64md(x))

#if _BYTE_ORDER == _LITTLE_ENDIAN

#define _QUAD_HIGHWORD 1
#define _QUAD_LOWWORD 0

#define __htobe16    __swap16
#define __htobe32    __swap32
#define __htobe64    __swap64
#define __htole16(x)    ((__uint16_t)(x))
#define __htole32(x)    ((__uint32_t)(x))
#define __htole64(x)    ((__uint64_t)(x))

#define __bemtoh16(_x) __mswap16(_x)
#define __bemtoh32(_x) __mswap32(_x)
#define __bemtoh64(_x) __mswap64(_x)

#define __htobem16(_x, _v) __swapm16((_x), (_v))
#define __htobem32(_x, _v) __swapm32((_x), (_v))
#define __htobem64(_x, _v) __swapm64((_x), (_v))

#endif /* _BYTE_ORDER == _LITTLE_ENDIAN */

#if _BYTE_ORDER == _BIG_ENDIAN

#define _QUAD_HIGHWORD 0
#define _QUAD_LOWWORD 1

#define __htobe16(x)    ((__uint16_t)(x))
#define __htobe32(x)    ((__uint32_t)(x))
#define __htobe64(x)    ((__uint64_t)(x))
#define __htole16    __swap16
#define __htole32    __swap32
#define __htole64    __swap64

#define __lemtoh16(_x) __mswap16(_x)
#define __lemtoh32(_x) __mswap32(_x)
#define __lemtoh64(_x) __mswap64(_x)

#define __htolem16(_x, _v) __swapm16((_x), (_v))
#define __htolem32(_x, _v) __swapm32((_x), (_v))
#define __htolem64(_x, _v) __swapm64((_x), (_v))

#endif /* _BYTE_ORDER == _BIG_ENDIAN */


#ifdef _KERNEL
/*
 * Fill in the __hto[bl]em{16,32,64} and __[bl]emtoh{16,32,64} macros
 * that haven't been defined yet
 */

#ifndef __bemtoh16
#define __bemtoh16(_x)        __htobe16(*(__uint16_t *)(_x))
#define __bemtoh32(_x)        __htobe32(*(__uint32_t *)(_x))
#define __bemtoh64(_x)        __htobe64(*(__uint64_t *)(_x))
#endif

#ifndef __htobem16
#define __htobem16(_x, _v)    (*(__uint16_t *)(_x) = __htobe16(_v))
#define __htobem32(_x, _v)    (*(__uint32_t *)(_x) = __htobe32(_v))
#define __htobem64(_x, _v)    (*(__uint64_t *)(_x) = __htobe64(_v))
#endif

#ifndef __lemtoh16
#define __lemtoh16(_x)        __htole16(*(__uint16_t *)(_x))
#define __lemtoh32(_x)        __htole32(*(__uint32_t *)(_x))
#define __lemtoh64(_x)        __htole64(*(__uint64_t *)(_x))
#endif

#ifndef __htolem16
#define __htolem16(_x, _v)    (*(__uint16_t *)(_x) = __htole16(_v))
#define __htolem32(_x, _v)    (*(__uint32_t *)(_x) = __htole32(_v))
#define __htolem64(_x, _v)    (*(__uint64_t *)(_x) = __htole64(_v))
#endif
#endif /* _KERNEL */

/* Public names */
#define LITTLE_ENDIAN    _LITTLE_ENDIAN
#define BIG_ENDIAN    _BIG_ENDIAN
#define PDP_ENDIAN    _PDP_ENDIAN
#define BYTE_ORDER    _BYTE_ORDER


/*
 * These are specified to be function-like macros to match the spec
 */
#define htobe16(x)    __htobe16(x)
#define htobe32(x)    __htobe32(x)
#define htobe64(x)    __htobe64(x)
#define htole16(x)    __htole16(x)
#define htole32(x)    __htole32(x)
#define htole64(x)    __htole64(x)

/* POSIX names */
#define be16toh(x)    __htobe16(x)
#define be32toh(x)    __htobe32(x)
#define be64toh(x)    __htobe64(x)
#define le16toh(x)    __htole16(x)
#define le32toh(x)    __htole32(x)
#define le64toh(x)    __htole64(x)

#define swap16(x) __swap16(x)
#define swap32(x) __swap32(x)
#define swap64(x) __swap64(x)

#define swap16_multi(v, n) do {                        \
    __size_t __swap16_multi_n = (n);                \
    __uint16_t *__swap16_multi_v = (v);                \
                                    \
    while (__swap16_multi_n) {                    \
        *__swap16_multi_v = swap16(*__swap16_multi_v);        \
        __swap16_multi_v++;                    \
        __swap16_multi_n--;                    \
    }                                \
} while (0)

/* original BSD names */
#define betoh16(x)    __htobe16(x)
#define betoh32(x)    __htobe32(x)
#define betoh64(x)    __htobe64(x)
#define letoh16(x)    __htole16(x)
#define letoh32(x)    __htole32(x)
#define letoh64(x)    __htole64(x)

#ifndef htons
/* these were exposed here before */
#define htons(x)    __htobe16(x)
#define htonl(x)    __htobe32(x)
#define ntohs(x)    __htobe16(x)
#define ntohl(x)    __htobe32(x)
#endif

/* ancient stuff */
#define    NTOHL(x) (x) = ntohl((u_int32_t)(x))
#define    NTOHS(x) (x) = ntohs((u_int16_t)(x))
#define    HTONL(x) (x) = htonl((u_int32_t)(x))
#define    HTONS(x) (x) = htons((u_int16_t)(x))

#ifdef _KERNEL
/* to/from memory conversions */
#define bemtoh16    __bemtoh16
#define bemtoh32    __bemtoh32
#define bemtoh64    __bemtoh64
#define htobem16    __htobem16
#define htobem32    __htobem32
#define htobem64    __htobem64
#define lemtoh16    __lemtoh16
#define lemtoh32    __lemtoh32
#define lemtoh64    __lemtoh64
#define htolem16    __htolem16
#define htolem32    __htolem32
#define htolem64    __htolem64
#endif /* _KERNEL */

#include <libkern/OSByteOrder.h>

#define htobe16 OSSwapHostToBigInt16
#define htobe32 OSSwapHostToBigInt32
#define htobe64 OSSwapHostToBigInt64
#define betoh16 OSSwapBigToHostInt16
#define betoh32 OSSwapBigToHostInt32
#define betoh64 OSSwapBigToHostInt64
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htole16 OSSwapHostToLittleInt16
#define htole32 OSSwapHostToLittleInt32
#define htole64 OSSwapHostToLittleInt64
#define letoh16 OSSwapLittleToHostInt16
#define letoh32 OSSwapLittleToHostInt32
#define letoh64 OSSwapLittleToHostInt64

#endif /* _SYS_ENDIAN_H_ */
