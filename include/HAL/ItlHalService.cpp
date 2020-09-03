/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/

#include "ItlHalService.hpp"

#define super OSObject
OSDefineMetaClassAndAbstractStructors(ItlHalService, OSObject)

bool ItlHalService::
initWithController(IOEthernetController *controller, IOWorkLoop *workloop, IOCommandGate *commandGate)
{
    this->controller = controller;
    this->controller->retain();
    this->mainWorkLoop = workloop;
    this->mainWorkLoop->retain();
    this->mainCommandGate = commandGate;
    this->mainCommandGate->retain();
    return true;
}

IOEthernetController *ItlHalService::
getController()
{
    return this->controller;
}

IOCommandGate *ItlHalService::
getMainCommandGate()
{
    return this->mainCommandGate;
}

IOWorkLoop *ItlHalService::
getMainWorkLoop()
{
    return this->mainWorkLoop;
}

void ItlHalService::
wakeupOn(void *ident)
{
//    XYLog("%s\n", __FUNCTION__);
    if (getMainCommandGate() == 0)
        return;
    else
        getMainCommandGate()->commandWakeup(ident);
}

int ItlHalService::
tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
//    XYLog("%s %s\n", __FUNCTION__, wmesg);
    IOReturn ret;
    if (getMainCommandGate() == 0) {
        IOSleep(timo);
        return 0;
    }
    if (timo == 0) {
        ret = getMainCommandGate()->runCommand(ident);
    } else {
        ret = getMainCommandGate()->runCommand(ident, &timo);
    }
    if (ret == kIOReturnSuccess)
        return 0;
    else
        return 1;
}

void ItlHalService::
free()
{
    XYLog("ItlHalService %s\n", __FUNCTION__);
    if (this->mainWorkLoop) {
        this->mainWorkLoop->release();
    }
    this->mainWorkLoop = NULL;
    if (this->mainCommandGate) {
        this->mainCommandGate->release();
    }
    this->mainCommandGate = NULL;
    if (this->controller) {
        this->controller->release();
    }
    this->controller = NULL;
    super::free();
}
