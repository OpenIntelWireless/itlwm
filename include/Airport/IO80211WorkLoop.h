/*
 *  IO80211WorkLoop.h
 *  IO80211Family
 *
 *  Created by Pete on 5/31/06.
 *  Copyright 2006 Apple Computer, Inc. All rights reserved.
 *
 */

#ifndef _IO80211WORKLOOP_H
#define _IO80211WORKLOOP_H

#include <Availability.h>
#include <IOKit/IOWorkLoop.h>

// This is necessary, because even the latest Xcode does not support properly targeting 11.0.
#ifndef __IO80211_TARGET
#error "Please define __IO80211_TARGET to the requested version"
#endif

class IO80211WorkLoop : public IOWorkLoop
{
    OSDeclareDefaultStructors( IO80211WorkLoop )

public:

    static IO80211WorkLoop * workLoop();

    virtual void openGate() APPLE_KEXT_OVERRIDE;
    virtual void closeGate() APPLE_KEXT_OVERRIDE;
    virtual int sleepGate( void * event, UInt32 interuptibleType ) APPLE_KEXT_OVERRIDE;
    virtual int sleepGateDeadline( void * event, UInt32 interuptibleType, AbsoluteTime deadline );
    virtual void wakeupGate( void * event, bool oneThread ) APPLE_KEXT_OVERRIDE;

};

#endif
