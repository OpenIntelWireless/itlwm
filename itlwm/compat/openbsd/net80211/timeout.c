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

extern IOWorkLoop *_fWorkloop;

void initTimeout(IOWorkLoop *workloop)
{
    _fWorkloop = workloop;
}

void releaseTimeout()
{
    _fWorkloop = NULL;
}

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
//    if (*t == NULL) {
//        *t = new CTimeout();
//    }
//    ((CTimeout*)*t)->to_func = fn;
//    ((CTimeout*)*t)->to_arg = arg;
}

int timeout_add_msec(CTimeout **to, int msecs)
{
//    if (*to == NULL) {
//        *to = new CTimeout();
//    }
//    CTimeout *cto = *to;
//    if (cto->tm) {
//        _fWorkloop->removeEventSource(cto->tm);
//        OSSafeReleaseNULL(cto->tm);
//    }
//    cto->tm = IOTimerEventSource::timerEventSource(cto, &CTimeout::timeoutOccurred);
//    if (cto->tm == NULL)
//        return 0;
//    if (_fWorkloop == NULL) {
//        IOLog("itlwm 啊啊啊啊啊啊啊啊啊啊啊啊啊,怎么是空的啊!!!!\n");
//        return 0;
//    }
//    _fWorkloop->addEventSource(cto->tm);
//    cto->tm->enable();
//    cto->tm->setTimeoutMS(msecs);
//    IOLog("itlwm %s\n", __func__);
    return 1;
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
//    if (((CTimeout*)*to) == NULL) {
//        IOLog("timeout_del timeout NULL\n");
//        return 0;
//    }
//    if (((CTimeout*)*to)->tm) {
//        ((CTimeout*)*to)->tm->cancelTimeout();
//        if (_fWorkloop) {
//            _fWorkloop->removeEventSource(((CTimeout*)*to)->tm);
//        }
//        OSSafeReleaseNULL(((CTimeout*)*to)->tm);
//    }
//    OSSafeReleaseNULL(*to);
    return 1;
}

int timeout_pending(CTimeout **to)
{
    if (!((CTimeout*)*to) || !((CTimeout*)*to)->tm || !((CTimeout*)*to)->tm->isEnabled()) {
        return 0;
    }
    return 1;
}

#endif /* timeout_cpp */
