//
//  _ifq.h
//  itlwm
//
//  Created by qcwap on 2020/3/1.
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

#ifndef _ifq_h
#define _ifq_h
#include <net/if_var.h>

static int ifq_oactive;

static inline void
ifq_set_oactive(IOPacketQueue **ifq)
{
    ifq_oactive = 1;
}

static inline void
ifq_clr_oactive(IOPacketQueue **ifq)
{
    ifq_oactive = 0;
}

static inline unsigned int
ifq_is_oactive(IOPacketQueue **ifq)
{
    return (ifq_oactive);
}

static inline mbuf_t
ifq_dequeue(IOPacketQueue **ifq)
{
    return (*ifq)->lockDequeue();
}

#endif /* _ifq_h */
