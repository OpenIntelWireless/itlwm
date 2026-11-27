//
//  IO80211WorkQueue.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef _IO80211WORKQUEUE_H
#define _IO80211WORKQUEUE_H

#include <Availability.h>
#include <IOKit/IOWorkLoop.h>

#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

class IO80211Controller;
class CCLogStream;

class IO80211WorkQueue : public IOWorkLoop {
    OSDeclareAbstractStructors(IO80211WorkQueue)
public:
    virtual IOThread getThread() const override;
    virtual void enableAllInterrupts() const override;
    virtual void disableAllInterrupts() const override;
    virtual IOReturn runAction(int (*)(OSObject*, void*, void*, void*, void*), OSObject*, void*, void*, void*, void*) override;
    virtual int commandSleep(void*, unsigned long long);
    virtual void commandWakeup(void*);
private: uint8_t _layout[0x50 - sizeof(IOWorkLoop)];
public: static IO80211WorkQueue *workQueue();
};
static_assert(sizeof(IO80211WorkQueue) == 0x50, "WCL ABI size");
#endif
