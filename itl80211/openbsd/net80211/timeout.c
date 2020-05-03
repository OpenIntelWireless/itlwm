//
//  timeout.cpp
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/30.
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

#ifndef timeout_cpp
#define timeout_cpp

#include <sys/timeout.h>
#include <IOKit/IOCommandGate.h>

extern IOWorkLoop *_fWorkloop;
extern IOCommandGate *_fCommandGate;

int splnet()
{
    //    _fWorkloop->disableAllInterrupts();
    //    _fWorkloop->disableAllEventSources();
    return 1;
}

void splx(int s)
{
    //    _fWorkloop->enableAllInterrupts();
    //    _fWorkloop->enableAllEventSources();
}

void timeout_set(CTimeout **t, void (*fn)(void *), void *arg)
{
    if (*t == NULL) {
        *t = new CTimeout();
        (*t)->isPending = false;
    }
    ((CTimeout*)*t)->to_func = fn;
    ((CTimeout*)*t)->to_arg = arg;
}

int timeout_add_msec(CTimeout **to, int msecs)
{
    if (*to == NULL) {
        return 0;
    }
    (*to)->isPending = true;
    return _fCommandGate->runAction(&CTimeout::timeout_add_msec, *to, _fWorkloop, &msecs) == kIOReturnSuccess ? 1 : 0;
}

int timeout_add_sec(CTimeout **to, int secs)
{
    return timeout_add_msec(to, secs * 1000);
}

int timeout_add_usec(CTimeout **to, int usecs)
{
    return timeout_add_msec(to, (int) usecs / 1000);
}

int timeout_del(CTimeout **to)
{
    //    IOLog("timeout_del\n");
    if ((*to) == NULL) {
        return 0;
    }
    return _fCommandGate->runAction(&CTimeout::timeout_del, *to) == kIOReturnSuccess ? 1 : 0;
}

int timeout_pending(CTimeout **to)
{
    if (*to != NULL && (*to)->isPending) {
        return 1;
    }
    return 0;
}

#endif /* timeout_cpp */
