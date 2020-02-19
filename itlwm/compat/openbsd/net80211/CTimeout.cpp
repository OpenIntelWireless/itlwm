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
    CTimeout *tm = (CTimeout*)owner;
    //callback
    tm->to_func(tm->to_arg);
}
