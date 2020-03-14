//
//  timeout.cpp
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/30.
//  Copyright © 2020 钟先耀. All rights reserved.
//

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
    }
    ((CTimeout*)*t)->to_func = fn;
    ((CTimeout*)*t)->to_arg = arg;
}

int timeout_add_msec(CTimeout **to, int msecs)
{
    if (*to == NULL) {
        *to = new CTimeout();
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
    IOLog("timeout_del\n");
    if (((CTimeout*)*to) == NULL) {
        IOLog("timeout_del timeout NULL\n");
        return 0;
    }
    return _fCommandGate->runAction(&CTimeout::timeout_del, *to) == kIOReturnSuccess ? 1 : 0;
}

int timeout_pending(CTimeout **to)
{
    if (!((CTimeout*)*to) || !((CTimeout*)*to)->tm || !((CTimeout*)*to)->tm->isEnabled()) {
        return 0;
    }
    return 1;
}

#endif /* timeout_cpp */
