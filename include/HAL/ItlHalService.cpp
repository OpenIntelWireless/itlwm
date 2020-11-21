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
    this->inner_attr = lck_attr_alloc_init();
    this->inner_gp_attr = lck_grp_attr_alloc_init();
    this->inner_gp = lck_grp_alloc_init("itlwm_tsleep", this->inner_gp_attr);
    this->inner_lock = lck_mtx_alloc_init(this->inner_gp, this->inner_attr);
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
    wakeup(ident);
}

int ItlHalService::
tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
//    XYLog("%s %s\n", __FUNCTION__, wmesg);
    struct timespec ts;
    int err;
    memset(&ts, 0, sizeof(struct timespec));
    ts.tv_nsec = timo;
    lck_mtx_lock(this->inner_lock);
    err = msleep(ident, this->inner_lock, priority, wmesg, &ts);
    lck_mtx_unlock(this->inner_lock);
    return err;
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
    if (this->inner_lock) {
        lck_attr_free(this->inner_attr);
        lck_mtx_free(this->inner_lock, this->inner_gp);
        lck_grp_free(this->inner_gp);
        lck_grp_attr_free(this->inner_gp_attr);
        this->inner_lock = NULL;
    }
    this->controller = NULL;
    super::free();
}
