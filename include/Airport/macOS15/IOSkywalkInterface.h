//
//  IOSkywalkInterface.h
//  AirportItlwm
//
//  Created by laobamac on 2026/10/5.
//  Copyright © 2026 laobamac. All rights reserved.
//


#ifndef IOSkywalkInterface_h
#define IOSkywalkInterface_h

#include <IOKit/IOService.h>

class IO80211Controller;
class CCLogStream;

class IOSkywalkInterface : public IOService {
    OSDeclareAbstractStructors(IOSkywalkInterface)
public:
    virtual void free() override;
    virtual bool init(OSDictionary*) override;
    virtual bool willTerminate(IOService*, unsigned int) override;
    virtual bool didTerminate(IOService*, unsigned int, bool*) override;
    virtual bool handleOpen(IOService*, unsigned int, void*) override;
    virtual void handleClose(IOService*, unsigned int) override;
    virtual bool handleIsOpen(IOService const*) const override;
    virtual IOReturn enable(unsigned int) = 0;
    virtual IOReturn disable(unsigned int) = 0;
    virtual IOReturn clientConnectWithTask(task*, IOService*, unsigned int);
    virtual void clientDisconnect(IOService*, unsigned int);
    virtual bool isTerminating();
    virtual void _RESERVEDIOSkywalkInterface0();
    virtual void _RESERVEDIOSkywalkInterface1();
    virtual void _RESERVEDIOSkywalkInterface2();
    virtual void _RESERVEDIOSkywalkInterface3();
    virtual void _RESERVEDIOSkywalkInterface4();
    virtual void _RESERVEDIOSkywalkInterface5();
    virtual void _RESERVEDIOSkywalkInterface6();
    virtual void _RESERVEDIOSkywalkInterface7();
    virtual void _RESERVEDIOSkywalkInterface8();
    virtual void _RESERVEDIOSkywalkInterface9();
    virtual void _RESERVEDIOSkywalkInterface10();
private: uint8_t _layout[0xb0 - sizeof(IOService)];
};
static_assert(sizeof(IOSkywalkInterface) == 0xb0, "WCL ABI size");
#endif
