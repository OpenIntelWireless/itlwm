//
//  FaultReporter.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef WCLFaultReporter_h
#define WCLFaultReporter_h

#include "../CCStream.h"
#include <IOKit/IOWorkLoop.h>

class CCDataStream : public CCStream {
    OSDeclareAbstractStructors(CCDataStream)
};

class CCFaultReporter : public IOService {
    OSDeclareDefaultStructors(CCFaultReporter)
public:
    static CCFaultReporter *withStreamWorkloop(CCDataStream *, IOWorkLoop *);
};

class CommonFaultReporter : public OSObject {
    OSDeclareAbstractStructors(CommonFaultReporter)
};

class IO80211FaultReporter : public CommonFaultReporter {
    OSDeclareDefaultStructors(IO80211FaultReporter)
public:
    static IO80211FaultReporter *allocWithParams(CCFaultReporter *);
};

#endif
