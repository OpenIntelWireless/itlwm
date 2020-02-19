//
//  random.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef random_h
#define random_h

#include <libkern/crypto/rand.h>

static inline void get_random_bytes(void *buf, int nbytes)
{
    random_buf(buf, nbytes);
}

#endif /* random_h */
