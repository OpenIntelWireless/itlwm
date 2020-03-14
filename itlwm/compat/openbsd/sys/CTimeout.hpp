//
//  CTimeout.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/30.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef CTimeout_h
#define CTimeout_h

#include <IOKit/IOTimerEventSource.h>
#include <libkern/c++/OSObject.h>
    
class CTimeout : public OSObject {
    OSDeclareDefaultStructors(CTimeout)
    
public:
    static void timeoutOccurred(OSObject* owner, IOTimerEventSource* timer);
    
    static IOReturn timeout_add_msec(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    static IOReturn timeout_del(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
public:
    IOTimerEventSource* tm;
    void (*to_func)(void *);        /* function to call */
    void *to_arg;                /* function argument */
};

#endif /* CTimeout_h */
