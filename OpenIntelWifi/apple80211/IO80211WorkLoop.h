/*
 *  IO80211WorkLoop.h
 *  Family
 *
 *  Created by Pete on 5/31/06.
 *  Copyright 2006 Apple Computer, Inc. All rights reserved.
 *
 */

#ifndef _IO80211WORKLOOP_H
#define _IO80211WORKLOOP_H
#include <IOKit/IOWorkLoop.h>

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
