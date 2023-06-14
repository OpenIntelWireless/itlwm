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
class CCPipeStatistics;
struct CCPipeOptions {
    uint64_t pipe_type;  // 0x0
    uint64_t log_data_type;  // 0x8
    uint64_t pipe_size;  // 0x10
    uint64_t min_log_size_notify;  // 0x18
    uint32_t notify_threshold;  // 0x20
    char     file_name[0x100];   // 0x24
    char     name[0xF0];    // 0x124
    char    pad8[0x10];     // 0x214
    uint32_t    pad9;       // 0x224
    uint32_t    pad10;     // 0x228
    uint64_t    file_options;  // 0x230
    uint64_t    log_policy;  // 0x238
    uint32_t    pad13;
    char    directory_name[0x100];   // 0x244
    uint8_t pad[0xC];
};

static_assert(offsetof(CCPipeOptions, pipe_size) == 0x10, "Invalid offset");
static_assert(offsetof(CCPipeOptions, file_name) == 0x24, "Invalid offset");
static_assert(offsetof(CCPipeOptions, name) == 0x124, "Invalid offset");
static_assert(offsetof(CCPipeOptions, pad9) == 0x224, "Invalid offset");
static_assert(offsetof(CCPipeOptions, pad10) == 0x228, "Invalid offset");
static_assert(offsetof(CCPipeOptions, file_options) == 0x230, "Invalid offset");
static_assert(offsetof(CCPipeOptions, log_policy) == 0x238, "Invalid offset");
static_assert(offsetof(CCPipeOptions, directory_name) == 0x244, "Invalid offset");
static_assert(sizeof(CCPipeOptions) == 0x350, "Invalid offset");


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
    static CCPipe *withOwnerNameCapacity(IOService *,char const*,char const*,CCPipeOptions const*);
    
public:
    uint8_t filter[0x90];
};

#endif /* CCPipe_h */
