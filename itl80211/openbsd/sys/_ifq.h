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
#include <IOKit/network/IOPacketQueue.h>

struct _ifqueue {
    unsigned int ifq_oactive;
    IOPacketQueue *queue;
};

void ifq_init(struct _ifqueue *ifq, struct _ifnet *ifp, unsigned int maxLen);

void ifq_destroy(struct _ifqueue *ifq);

void ifq_flush(struct _ifqueue *ifq);

bool ifq_empty(struct _ifqueue *ifq);

uint32_t ifq_len(struct _ifqueue *ifq);

void ifq_set_maxlen(struct _ifqueue *ifq, uint32_t maxLen);

void ifq_set_oactive(struct _ifqueue *ifq);

unsigned int ifq_is_oactive(struct _ifqueue *ifq);

void ifq_clr_oactive(struct _ifqueue *ifq);

mbuf_t ifq_dequeue(struct _ifqueue *ifq);

int ifq_enqueue(struct _ifqueue *ifq, mbuf_t m);

#endif /* _ifq_h */
