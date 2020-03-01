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
    IOLog("itlwm %s\n", __func__);
    CTimeout *tm = OSDynamicCast(CTimeout, owner);
    if (tm == NULL) {
        IOLog("itlwm tm == NULL!!!\n");
    }
    //callback
//    tm->to_func(tm->to_arg);
}
