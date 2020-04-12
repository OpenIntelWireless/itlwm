//
//  random.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
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

#ifndef random_h
#define random_h

#include <libkern/crypto/rand.h>

static inline void get_random_bytes(void *buf, int nbytes)
{
    random_buf(buf, nbytes);
}

#endif /* random_h */
