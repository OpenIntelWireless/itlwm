//
//  types.h
//  AppleIntelWifiAdapter
//
//  Created by qcwap on 2020/1/5.
//  Copyright © 2020 钟先耀. All rights reserved.
//

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

#ifndef types_h
#define types_h

#include <IOKit/IOTypes.h>
#include <libkern/OSAtomic.h>
#include <linux/bitfield.h>

#define local_bh_disable()
#define local_bh_enable()

#define NUM_DEFAULT_KEYS 4
#define NUM_DEFAULT_MGMT_KEYS 2

#define gfp_t int

#define __packed __attribute__((packed)) __attribute__((aligned(1)))
#define __aligned(x)        __attribute__((aligned(x)))
#define __must_check        __attribute__((warn_unused_result))

/*
#define MODULE_FIRMWARE(fw)
#define MODULE_DESCRIPTION(x)
#define MODULE_AUTHOR(x)
#define MODULE_LICENSE(x)
 

#define __init
#define __exit


#define module_init(x)
#define module_exit(x)
 */

#define pr_info(x)

#define __rcu

# define __acquires(x)
# define __releases(x)
# define __acquire(x) (void)0
# define __release(x) (void)0

#define might_sleep()

#define __bitwise
#define __force

#define list_head       queue_entry

#ifndef __WARN_printf
/*
 * To port this properly we'd have to port warn_slowpath_null(),
 * which I'm lazy to do so just do a regular print for now. If you
 * want to port this read kernel/panic.c
 */
#define __WARN_printf(func, line, arg...)   do { IOLog("(AppleIntelWifiAdapter) (%s:%d) WARN", func, line);} while (0);
#endif

#ifndef unlikely
#include <linux/kernel.h>
#endif

#ifndef WARN_ON_ONCE
#define WARN_ON_ONCE(condition, fmt...) ({ \
    static int __warned; \
    int __ret_warn_once = !!(condition); \
        \
    if(unlikely(__ret_warn_once)) \
        if(WARN_ON(!__warned, fmt...)) \
            __warned = 1;    \
    unlikely(__ret_warn_once); \
    (bool)__ret_warn_once; \
})
#endif

#ifndef WARN_ON
#define WARN_ON(condition, fmt...) ({ \
    int __ret_warn_on = !!(condition); \
    if(unlikely(__ret_warn_on)) \
        __WARN_printf(__FUNCTION__, __LINE__, fmt...) \
    unlikely(__ret_warn_on); \
    (bool)(__ret_warn_on);\
})
#endif

#define __stringify OS_STRINGIFY

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#define XYLog(fmt, x...)\
do\
{\
kprintf("%s: " fmt, "itlwm", ##x);\
}while(0)

typedef UInt8  u8;
typedef UInt16 u16;
typedef UInt32 u32;
typedef UInt64 u64;

typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;

typedef  SInt16 __be16;
typedef  SInt32 __be32;
typedef  SInt64 __be64;
typedef  SInt16 __le16;
typedef  SInt32 __le32;
typedef  SInt64 __le64;

typedef SInt8  s8;
typedef SInt16 s16;
typedef SInt32 s32;
typedef SInt64 s64;

typedef s8  __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;

typedef UInt16 __sum16;

typedef u64 dma_addr_t;

#define U8_MAX        ((u8)~0U)
#define S8_MAX        ((s8)(U8_MAX >> 1))
#define S8_MIN        ((s8)(-S8_MAX - 1))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define lower_32_bits(n) ((u32)(n))

#define __cpu_to_le64(x) ((__force __le64)(__u64)(x))
#define __le64_to_cpu(x) ((__force __u64)(__le64)(x))
#define __cpu_to_le32(x) ((__force __le32)(__u32)(x))
#define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
#define __cpu_to_le16(x) ((__force __le16)(__u16)(x))
#define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
#define __cpu_to_be64(x) ((__force __be64)__swab64((x)))
#define __be64_to_cpu(x) __swab64((__force __u64)(__be64)(x))
#define __cpu_to_be32(x) ((__force __be32)__swab32((x)))
#define __be32_to_cpu(x) __swab32((__force __u32)(__be32)(x))
#define __cpu_to_be16(x) ((__force __be16)__swab16((x)))
#define __be16_to_cpu(x) __swab16((__force __u16)(__be16)(x))

#define cpu_to_le64 __cpu_to_le64
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le32 __cpu_to_le32
#define le32_to_cpu __le32_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define le16_to_cpu __le16_to_cpu
#define cpu_to_be64 OSSwapHostToBigInt64
#define be64_to_cpu OSSwapBigToHostInt64
#define cpu_to_be32 OSSwapHostToBigInt32
#define be32_to_cpu OSSwapBigToHostInt32
#define cpu_to_be16 OSSwapHostToBigInt16
#define be16_to_cpu OSSwapBigToHostInt16

static inline __u16 __be16_to_cpup(const __be16 *p)
{
    return (__force __u16)*p;
}

static inline __u32 __be32_to_cpup(const __be32 *p)
{
    return (__force __u32)*p;
}

static inline __be32 __cpu_to_be32p(const __u32 *p)
{
    return (__force __be32)*p;
}

static inline __u64 __be64_to_cpup(const __be64 *p)
{
    return (__force __u64)*p;
}

static inline __be64 __cpu_to_be64p(const __u64 *p)
{
    return (__force __be64)*p;
}

static inline __u32 __le32_to_cpup(const __le32 *p)
{
    return (__force __u32)*p;
}

static inline __u16 __le16_to_cpup(const __le16 *p)
{
    return (__force __u16)*p;
}

#define le16_to_cpup(_a_) ((__uint16_t)(*(const uint16_t *)(_a_)))
#define le32_to_cpup(_a_) ((__uint32_t)(*(const uint32_t *)(_a_)))

static inline u32 get_unaligned_le32(const void *p)
{
    return le32_to_cpup((__le32 *)p);
}

static inline u32 get_unaligned_le16(const void *p)
{
    return le16_to_cpup((__le16 *)p);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
    *((__le32 *)p) = cpu_to_le32(val);
}

static inline unsigned int hweight8(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x55);
    res = (res & 0x33) + ((res >> 2) & 0x33);
    return (res + (res >> 4)) & 0x0F;
}

static inline unsigned int hweight16(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x5555);
    res = (res & 0x3333) + ((res >> 2) & 0x3333);
    res = (res + (res >> 4)) & 0x0F0F;
    return (res + (res >> 8)) & 0x00FF;
}

static inline unsigned int hweight32(unsigned int w)
{
    unsigned int res = w - ((w >> 1) & 0x55555555);
    res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
    res = (res + (res >> 4)) & 0x0F0F0F0F;
    res = res + (res >> 8);
    return (res + (res >> 16)) & 0x000000FF;
}

static inline unsigned long hweight64(uint64_t w)
{
    uint64_t res = w - ((w >> 1) & 0x5555555555555555ul);
    res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
    res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
    res = res + (res >> 8);
    res = res + (res >> 16);
    return (res + (res >> 32)) & 0x00000000000000FFul;
}

static inline uint64_t field_multiplier(uint64_t field)
{
    return field & -field;
}

static inline uint64_t field_mask(uint64_t field)
{
    return field / field_multiplier(field);
}

/**
 * sizeof_field(TYPE, MEMBER)
 *
 * @TYPE: The structure containing the field of interest
 * @MEMBER: The field to return the size of
 */
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

/**
 * offsetofend(TYPE, MEMBER)
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 */
#define offsetofend(TYPE, MEMBER) \
    (offsetof(TYPE, MEMBER)    + sizeof_field(TYPE, MEMBER))

#define ____MAKE_OP(type,base,to,from)                    \
static inline __##type type##_encode_bits(base v, base field)    \
{                                    \
    return to((v & field_mask(field)) * field_multiplier(field));    \
}                                    \
static inline __##type type##_replace_bits(__##type old,    \
                    base val, base field)        \
{                                    \
    return (old & ~to(field)) | type##_encode_bits(val, field);    \
}                                    \
static inline void type##p_replace_bits(__##type *p,        \
                    base val, base field)        \
{                                    \
    *p = (*p & ~to(field)) | type##_encode_bits(val, field);    \
}                                    \
static inline base type##_get_bits(__##type v, base field)    \
{                                    \
    return (from(v) & field)/field_multiplier(field);        \
}
#define __MAKE_OP(size)                            \
    ____MAKE_OP(le##size,u##size,cpu_to_le##size,le##size##_to_cpu)    \
    ____MAKE_OP(be##size,u##size,cpu_to_be##size,be##size##_to_cpu)    \
    ____MAKE_OP(u##size,u##size,,)
____MAKE_OP(u8,u8,,)
__MAKE_OP(16)
__MAKE_OP(32)
__MAKE_OP(64)
#undef __MAKE_OP
#undef ____MAKE_OP

#define atomic_t    volatile SInt32
#define atomic64_t  volatile SInt64

#define ETHTOOL_FWVERS_LEN    32


#define RT_ALIGN_T(u, uAlignment, type) ( ((type)(u) + ((uAlignment) - 1)) & ~(type)((uAlignment) - 1) )
#define RT_ALIGN_Z(cb, uAlignment)              RT_ALIGN_T(cb, uAlignment, size_t)
#define LNX_ALIGN RT_ALIGN_Z

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define _ALIGN(x, a)         ALIGN_MASK(x, (typeof(x))(a) - 1)

#define _usec_delay(x)           IODelay(x)
#define _msec_delay(x)           IOSleep(x)
#define _udelay(x)               IODelay(x)
#define _mdelay(x)               IODelay(1000*(x))
#define _msleep(x)               IOSleep(x)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define usleep_range(min, max)    _msleep(DIV_ROUND_UP(min, 1000))

#endif /* types_h */
