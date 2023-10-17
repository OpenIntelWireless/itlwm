//
//  CCDataPipe.h
//  itlwm
//
//  Created by qcwap on 2023/6/14.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef CCDataPipe_h
#define CCDataPipe_h

#include "CCPipe.h"
#include <IOKit/IOTimerEventSource.h>

class CCDataPipeBlob;

class CCDataPipe : public CCPipe {
    OSDeclareDefaultStructors(CCDataPipe)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual bool start( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual void stop( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual void detach( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    LIBKERN_RETURNS_RETAINED IOUserClient ** handler ) APPLE_KEXT_OVERRIDE;
    virtual bool clientClose(void) APPLE_KEXT_OVERRIDE;
    virtual void *getCoreCapturePipeReporter(void) APPLE_KEXT_OVERRIDE;
    virtual bool isClientConnected(void) APPLE_KEXT_OVERRIDE;
    virtual bool startPipe(void) APPLE_KEXT_OVERRIDE;
    virtual void stopPipe(void) APPLE_KEXT_OVERRIDE;
    virtual UInt generateStreamId(void) APPLE_KEXT_OVERRIDE;
    virtual bool addInitCapture(void) APPLE_KEXT_OVERRIDE;
    virtual void removeInitCapture(void) APPLE_KEXT_OVERRIDE;
    virtual void removeCapture(void) APPLE_KEXT_OVERRIDE;
    virtual bool profileLoaded(void) APPLE_KEXT_OVERRIDE;
    virtual bool profileRemoved(void) APPLE_KEXT_OVERRIDE;
    virtual bool capture(CCTimestamp *,char const*) APPLE_KEXT_OVERRIDE;
    virtual bool capture(CCTimestamp,char const*) APPLE_KEXT_OVERRIDE;
    virtual bool hasPrivilege(void) APPLE_KEXT_OVERRIDE;
    virtual bool hasPrivilegeAdministrator(task_t) APPLE_KEXT_OVERRIDE;
    virtual bool initWithOwnerNameCapacity(IOService *,char const*,char const*,CCPipeOptions const*) APPLE_KEXT_OVERRIDE;
    virtual OSString *getClassName(void) APPLE_KEXT_OVERRIDE;
    virtual void setCCaptureInRegistry(void) APPLE_KEXT_OVERRIDE;
    virtual unsigned long getPipeSize(void) APPLE_KEXT_OVERRIDE;
    virtual void setPipeSize(unsigned long) APPLE_KEXT_OVERRIDE;
    virtual void freeCCCaptureObject(void) APPLE_KEXT_OVERRIDE;
    virtual void *getPipeCallbacks(void) APPLE_KEXT_OVERRIDE;
    virtual IOService *getProvider(void) APPLE_KEXT_OVERRIDE;
    virtual void *getCurrentOptions(void) APPLE_KEXT_OVERRIDE;
    virtual void *getDriverOptions(void) APPLE_KEXT_OVERRIDE;
    virtual UInt getLoggingFlags(void) APPLE_KEXT_OVERRIDE;
    virtual unsigned long getRingEntryMaxTimeMs(void) APPLE_KEXT_OVERRIDE;
    virtual unsigned long getRingEntrySleepTimeMs(void) APPLE_KEXT_OVERRIDE;
    virtual CCPipeStatistics *getStatistics(void) APPLE_KEXT_OVERRIDE;
    virtual void setStatistics(CCPipeStatistics *) APPLE_KEXT_OVERRIDE;
    virtual void publishStatistics(void) APPLE_KEXT_OVERRIDE;
    virtual void updateStatistics(bool) APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureAllReports(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateAllReports(void) APPLE_KEXT_OVERRIDE;
    virtual void *createReportSet(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn enqueueBlob(CCDataPipeBlob *);
    virtual bool dequeueBlob(CCDataPipeBlob **);
    virtual void freeResources(void);
    virtual void notifyTimeout(IOTimerEventSource *);
    
public:
    uint8_t filter[0x98];
};

#endif /* CCDataPipe_h */
