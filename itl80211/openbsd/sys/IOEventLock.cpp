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

#include "IOEventLock.hpp"
#include <IOKit/network/IOEthernetController.h>

#define super IOEventSource
OSDefineMetaClassAndStructors(IOEventLock, IOEventSource)

void IOEventLock::free()
{
    super::free();
}

bool IOEventLock::init(OSObject *owner)
{
    IOEthernetController *ctl = OSDynamicCast(IOEthernetController, owner);
    if (!ctl) {
        return false;
    }
    if (!super::init(owner, NULL)) {
        return false;
    }
    setWorkLoop(ctl->getWorkLoop());
    return true;
}

void IOEventLock::unlock()
{
    openGate();
}

void IOEventLock::lock()
{
    closeGate();
}
