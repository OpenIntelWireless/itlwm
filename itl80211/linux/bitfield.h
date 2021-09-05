//
//  bitfield.h
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

#ifndef bitfield_h
#define bitfield_h

#include <libkern/OSTypes.h>
#include <libkern/OSAtomic.h>

#define BITS_PER_LONG 64

#define BITS_PER_LONG_LONG 64

#define BIT(nr)            (1UL << (nr))
#define BIT_ULL(nr)        (1ULL << (nr))
#define BIT_MASK(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)    (1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)    ((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE        8
#define BITS_TO_LONGS(nr)    DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_PREP(_mask, _val)                        \
({                                \
((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);    \
})

static inline int
find_first_zero_bit(volatile void *p, int max)
{
    int b;
    volatile u_int *ptr = (volatile u_int *)p;

    for (b = 0; b < max; b += 32) {
        if (ptr[b >> 5] != ~0) {
            for (;;) {
                if ((ptr[b >> 5] & (1 << (b & 0x1f))) == 0)
                    return b;
                b++;
            }
        }
    }
    return max;
}

static inline int
find_next_zero_bit(volatile void *p, int max, int b)
{
    volatile u_int *ptr = (volatile u_int *)p;

    for (; b < max; b += 32) {
        if (ptr[b >> 5] != ~0) {
            for (;;) {
                if ((ptr[b >> 5] & (1 << (b & 0x1f))) == 0)
                    return b;
                b++;
            }
        }
    }
    return max;
}

static inline int
find_first_bit(volatile void *p, int max)
{
    int b;
    volatile u_int *ptr = (volatile u_int *)p;

    for (b = 0; b < max; b += 32) {
        if (ptr[b >> 5] != 0) {
            for (;;) {
                if (ptr[b >> 5] & (1 << (b & 0x1f)))
                    return b;
                b++;
            }
        }
    }
    return max;
}

static inline int
find_next_bit(volatile void *p, int max, int b)
{
    volatile u_int *ptr = (volatile u_int *)p;

    for (; b < max; b+= 32) {
        if (ptr[b >> 5] != 0) {
            for (;;) {
                if (ptr[b >> 5] & (1 << (b & 0x1f)))
                    return b;
                b++;
            }
        }
    }
    return max;
}

static inline int
find_last_bit(volatile void *p, int max)
{
    int b;
    volatile u_int *ptr = (volatile u_int *)p;

    for (b = max; b > 0; b -= 32) {
        if (ptr[b >> 5] != 0) {
            for (;;) {
                if (ptr[b >> 5] & (1 << (b & 0x1f)))
                    return b;
                b--;
            }
        }
    }
    return max;
}

#define for_each_set_bit(bit, addr, size) \
        for ((bit) = find_first_bit((addr), (size));        \
            (bit) < (size);                    \
            (bit) = find_next_bit((addr), (size), (bit) + 1))

#define GENMASK(h, l) \
    (((~(0UL)) - ((1UL) << (l)) + 1) & \
     (~(0UL) >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK_ULL(h, l) \
    (((~(0ULL)) - ((1ULL) << (l)) + 1) & \
     (~(0ULL) >> (BITS_PER_LONG_LONG - 1 - (h))))

static inline UInt64 OSBitwiseAtomic64(unsigned long and_mask, unsigned long or_mask, unsigned long xor_mask, unsigned long * value)
{
    unsigned long    oldValue;
    unsigned long    newValue;

    do {
        oldValue = *value;
        newValue = ((oldValue & and_mask) | or_mask) ^ xor_mask;
    } while (! OSCompareAndSwap64(oldValue, newValue, value));
    
    return oldValue;
}

static inline unsigned long OSBitAndAtomic64(unsigned long mask, unsigned long * value)
{
    return OSBitwiseAtomic64(mask, 0, 0, value);
}

static inline unsigned long OSBitOrAtomic64(unsigned long mask, unsigned long * value)
{
    return OSBitwiseAtomic64(-1, mask, 0, value);
}

static inline void set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    OSBitOrAtomic64(mask, p);
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    OSBitAndAtomic64(~mask, p);
}

static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    unsigned long old;
    
    old = *p;
    *p = old | mask;
    
    return (old & mask) != 0;
}

static inline int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
    unsigned long old;
    
    old = *p;
    *p = old & ~mask;
    
    return (old & mask) != 0;
}

static inline int
test_bit(int nr, const volatile unsigned long *addr)
{
    return (OSAddAtomic(0, addr) & (1 << nr)) != 0;
}

static inline int linux_fls(int x)
{
    int r = 32;
    
    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

#endif /* bitfield_h */
