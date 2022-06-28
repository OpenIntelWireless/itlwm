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
free()
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
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
