//
//  ItlIwm.cpp
//  itlwm
//
//  Created by zhongxianyao on 2020/8/29.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "ItlIwm.hpp"

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlIwm, ItlHalService)

void ItlIwm::watchdogAction(IOTimerEventSource *timer)
{
    iwm_watchdog(&com.sc_ic.ic_ac.ac_if);
    timer->setTimeoutMS(1000);
}
