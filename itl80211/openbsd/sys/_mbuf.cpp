//
//  _mbuf.cpp
//  itlwm
//
//  Created by qcwap on 2020/6/14.
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

#include <sys/_mbuf.h>
extern "C" {
#include <net/bpf.h>
}
#include <IOKit/IOCommandGate.h>

extern IOCommandGate *_fCommandGate;

struct network_header {
    char pad[0x48];
};

static IOReturn _if_input(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    mbuf_t m;
    bool isEmpty = true;
    struct _ifnet *ifq = (struct _ifnet *)arg0;
    struct mbuf_list *ml = (struct mbuf_list *)arg1;
    
    MBUF_LIST_FOREACH(ml, m) {
        if (ifq->iface == NULL) {
            panic("%s ifq->iface == NULL!!!\n", __FUNCTION__);
            break;
        }
        if (m == NULL) {
            XYLog("%s m == NULL!!!\n", __FUNCTION__);
            continue;
        }
        //        XYLog("%s %d 啊啊啊啊 ifq->iface->inputPacket(m) hdr_len=%d len=%d\n", __FUNCTION__, __LINE__, mbuf_pkthdr_len(m), mbuf_len(m));
        isEmpty = false;
        ifq->iface->inputPacket(m, 0, IONetworkInterface::kInputOptionQueuePacket);
        if (ifq->netStat != NULL) {
            ifq->netStat->inputPackets++;
        }
    }
    if (!isEmpty) {
        ifq->iface->flushInputQueue();
    }
    return kIOReturnSuccess;
}

int if_input(struct _ifnet *ifq, struct mbuf_list *ml)
{
    return _fCommandGate->runAction((IOCommandGate::Action)_if_input, ifq, ml);
}

