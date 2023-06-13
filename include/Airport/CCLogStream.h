//
//  CCLogStream.h
//  itlwm
//
//  Created by qcwap on 2023/6/14.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef CCLogStream_h
#define CCLogStream_h

#include <IOKit/IOService.h>
#include "CCStream.h"

enum CCStreamLogLevel
{
    LEVEL_1,
};

class CCLogStream : public CCStream {
    OSDeclareDefaultStructors(CCLogStream)
    
public:
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool init(OSDictionary *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn configureReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual IOReturn updateReport(IOReportChannelList *,UInt,void *,void *) APPLE_KEXT_OVERRIDE;
    virtual bool start(IOService *) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *) APPLE_KEXT_OVERRIDE;
    virtual bool attach( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual void detach( IOService * provider ) APPLE_KEXT_OVERRIDE;
    virtual bool profileLoaded(void) APPLE_KEXT_OVERRIDE;
    virtual bool profileRemoved(void) APPLE_KEXT_OVERRIDE;
    virtual CCLogStream const *initWithPipeAndName(CCPipe *,char const*,CCStreamOptions const*) APPLE_KEXT_OVERRIDE;
    virtual void setLevel(CCStreamLogLevel);
    virtual CCStreamLogLevel getLevel(void);
    virtual void setFlags(unsigned long long);
    virtual unsigned long long getFlags(void);
    virtual void setLogFlag(unsigned long long);
    virtual void clearLogFlag(unsigned long long);
    virtual void setConsoleLevel(CCStreamLogLevel);
    virtual void setConsoleFlags(unsigned long long);
    virtual unsigned long long getConsoleFlags(void);
    virtual void setConsoleLogFlag(unsigned long long);
    virtual void clearConsoleLogFlag(unsigned long long);
    
public:
    uint8_t filter[0x98];
};

#endif /* CCLogStream_h */

