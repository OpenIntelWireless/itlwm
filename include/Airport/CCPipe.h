//
//  CCPipe.h
//  itlwm
//
//  Created by qcwap on 2023/6/14.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef CCPipe_h
#define CCPipe_h

#include <IOKit/IOService.h>

class CCTimestamp;
class CCPipeOptions;
class CCPipeStatistics;

class CCPipe : public IOService {
    OSDeclareAbstractStructors(CCPipe)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual void detach( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
    UInt32 type, OSDictionary * properties,
    LIBKERN_RETURNS_RETAINED IOUserClient ** handler ) = 0;
    virtual bool clientClose(void) = 0;
    virtual void *getCoreCapturePipeReporter(void);
    virtual bool isClientConnected(void) = 0;
    virtual bool startPipe(void);
    virtual void stopPipe(void);
    virtual UInt generateStreamId(void);
    virtual bool addInitCapture(void);
    virtual void removeInitCapture(void);
    virtual void removeCapture(void);
    virtual bool profileLoaded(void);
    virtual bool profileRemoved(void);
    virtual bool capture(CCTimestamp *,char const*) = 0;
    virtual bool capture(CCTimestamp,char const*) = 0;
    virtual bool hasPrivilege(void);
    virtual bool hasPrivilegeAdministrator(task_t);
    virtual bool initWithOwnerNameCapacity(IOService *,char const*,char const*,CCPipeOptions const*);
    virtual OSString *getClassName(void);
    virtual void setCCaptureInRegistry(void);
    virtual unsigned long getPipeSize(void);
    virtual void setPipeSize(unsigned long);
    virtual void freeCCCaptureObject(void);
    virtual void *getPipeCallbacks(void);
    virtual IOService *getProvider(void);
    virtual void *getCurrentOptions(void);
    virtual void *getDriverOptions(void);
    virtual UInt getLoggingFlags(void);
    virtual unsigned long getRingEntryMaxTimeMs(void);
    virtual unsigned long getRingEntrySleepTimeMs(void);
    virtual CCPipeStatistics *getStatistics(void);
    virtual void setStatistics(CCPipeStatistics *);
    virtual void publishStatistics(void);
    virtual void updateStatistics(bool);
    virtual IOReturn configureAllReports(void);
    virtual IOReturn updateAllReports(void);
    virtual void *createReportSet(void);
    
public:
    uint8_t filter[0x90];
};

#endif /* CCPipe_h */
