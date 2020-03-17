//
//  CTimeout.cpp
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/30.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "CTimeout.hpp"

void CTimeout::timeoutOccurred(OSObject* owner, IOTimerEventSource* timer)
{
    IOLog("itlwm %s\n", __FUNCTION__);
    if (owner == NULL) {
        IOLog("itlwm tm owner == NULL!!!\n");
    }
    CTimeout *tm = OSDynamicCast(CTimeout, owner);
    if (tm == NULL) {
        IOLog("itlwm tm == NULL!!!\n");
        return;
    }
    //callback
    tm->to_func(tm->to_arg);
}

IOReturn CTimeout::timeout_add_msec(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    IOWorkLoop *wl = (IOWorkLoop*)arg1;
    int msecs = *(int*)arg2;
    CTimeout *cto = (CTimeout *)arg0;
    if (cto->tm == NULL) {
        cto->tm = IOTimerEventSource::timerEventSource(cto, &CTimeout::timeoutOccurred);
        if (cto->tm == NULL) {
            return 0;
        }
        wl->addEventSource(cto->tm);
    }
    cto->tm->enable();
    cto->tm->setTimeoutMS(msecs);
    IOLog("itlwm %s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn CTimeout::timeout_del(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    CTimeout *cto = (CTimeout *)arg0;
    if (cto->tm) {
        cto->tm->cancelTimeout();
    }
    return kIOReturnSuccess;
}
