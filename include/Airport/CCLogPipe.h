//
//  CCLogPipe.h
//  itlwm
//
//  Created by qcwap on 2023/6/14.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef CCLogPipe_h
#define CCLogPipe_h

#include "CCPipe.h"
#include "CCLogStream.h"
#include <IOKit/IOTimerEventSource.h>

typedef int CCLogPolicy;
typedef int CCLogState;
class CCLogMetadata;

class CCLogPipe : public CCPipe {
    OSDeclareDefaultStructors(CCLogPipe)
    
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
    virtual void log(uint,CCStreamLogLevel,char const*,unsigned long long,bool,bool);
    virtual void log(uint,char const*,unsigned long long,unsigned long long,unsigned long long);
    virtual void log(uint,char const*,unsigned long long);
    virtual bool unmapPipe(void);
    virtual void setNotifyTimeout(uint);
    virtual void setWatermarkLevelToNotify(unsigned long);
    virtual bool getPolicy(CCLogPolicy *);
    virtual void setPolicy(CCLogPolicy);
    virtual void setStreamLogFlags(char const*,unsigned long long);
    virtual void updateStreamLogFlags(char const*,char const*,uint);
    virtual void setStreamLogLevel(char const*,CCStreamLogLevel);
    virtual void setStreamConsoleLogFlags(char const*,unsigned long long);
    virtual void setStreamConsoleLogLevel(char const*,CCStreamLogLevel);
    virtual void updateStreamConsoleLogFlags(char const*,char const*,uint);
    virtual IOReturn getUserSpaceNotificationPort(unsigned long long *);
    virtual void notifyUserSpace(void);
    virtual bool willDropMessage(uint);
    virtual char *getScratchBuffer(unsigned long,unsigned long *,uint);
    virtual void putScratchBuffer(char *,int);
    virtual void resizeScratchBuffer(char *,unsigned long,unsigned long *);
    virtual bool reserveRingEntry(unsigned long long,uint,int *);
    virtual UInt getLogIdentifier(void);
    virtual void freeResources(void);
    virtual void notifyTimeout(IOTimerEventSource *);
    virtual void log(CCStreamLogLevel,char const*,unsigned long long,unsigned long long,CCLogState);
    virtual bool isValidCCLogMetaData(CCLogMetadata volatile*);
    virtual bool isValidStreamLogLevel(CCStreamLogLevel);
    virtual bool isPtrInRing(void *);
    virtual void addOffset(uint volatile&,unsigned long,unsigned long);
    virtual UInt calculateFreeBufferLength(uint,uint);
    virtual void incrementRingPtr(unsigned char volatile*&,unsigned long);
    virtual void decrementRingPtr(unsigned char volatile*&,unsigned long);
    virtual void freeLogBuffer(unsigned long);
    virtual const char *getLogLevelShortName(CCStreamLogLevel);
    virtual CCLogStream *findStream(char const*);
    virtual void releaseStream(CCLogStream *);
    virtual void *findStreamEntry(char const*);
    virtual bool initScratchBuffers(unsigned long,unsigned long);
    virtual void freeScratchBuffers(void);
    
public:
    uint8_t filter[0x98];
};

#endif /* CCLogPipe_h */
