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
    return 1;
}

void splx(int s)
{
}

void timeout_set(CTimeout **t, void (*fn)(void *), void *arg)
{
    _fCommandGate->runAction(&CTimeout::timeout_set, t, (void*)fn, arg);
}

int timeout_add_msec(CTimeout **to, int msecs)
{
    if (*to == NULL) {
        return 0;
    }
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
    return _fCommandGate->runAction(&CTimeout::timeout_del, *to, _fWorkloop) == kIOReturnSuccess ? 1 : 0;
}

int timeout_free(CTimeout **to)
{
    return _fCommandGate->runAction(&CTimeout::timeout_free, to, _fWorkloop) == kIOReturnSuccess ? 1 : 0;
}

int timeout_pending(CTimeout **to)
{
    return _fCommandGate->runAction(&CTimeout::timeout_pending, to) == kIOReturnSuccess ? 1 : 0;
}

int timeout_initialized(CTimeout **to)
{
    return (*to) != NULL;
}

#endif /* timeout_cpp */
