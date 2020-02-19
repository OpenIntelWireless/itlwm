//
//  _arc4random.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _arc4random_h
#define _arc4random_h

#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/random.h>

#include <IOKit/IOLib.h>

/* Add platform entropy 32 bytes (256 bits) at a time. */
#define ADD_ENTROPY 32

/* Re-seed from the platform RNG after generating this many bytes. */
#define BYTES_BEFORE_RESEED 1600000

static inline u_int32_t arc4random()
{
    u_int32_t r;
    read_random(&r, sizeof(r));
    return r;
}

static inline void arc4random_buf(void *buf, size_t n)
{
    read_random(buf, (u_int)n);
}

static inline u_int32_t arc4random_uniform(u_int32_t upper_bound)
{
    u_int32_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;) {
        r = arc4random();
        if (r >= min)
            break;
    }

    return r % upper_bound;
}

#endif
