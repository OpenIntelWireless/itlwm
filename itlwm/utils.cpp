//
//  utils.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef CUSTOM_HEADER
#include "itlwm.hpp"
#else
#include "OpenWifi.hpp"
#endif
#include <IOKit/IOLib.h>

void* itlwm::
malloc(vm_size_t len, int type, int how)
{
    void* addr = IOMalloc(len + sizeof(vm_size_t));
    *((vm_size_t*) addr) = len;
    return (void*)((uint8_t*)addr + sizeof(vm_size_t));
}

void itlwm::
free(void* addr)
{
    void* actual_addr = (void*)((uint8_t*)addr - sizeof(vm_size_t));
    vm_size_t len = *((vm_size_t*) actual_addr);
    IOFree(actual_addr, len + sizeof(vm_size_t));
}

void itlwm::
free(void *addr, int type, vm_size_t len)
{
    IOFree(addr, len);
}

int itlwm::
iwm_send_bt_init_conf(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    struct iwm_bt_coex_cmd bt_cmd;

    bt_cmd.mode = htole32(IWM_BT_COEX_WIFI);
    bt_cmd.enabled_modules = htole32(IWM_BT_COEX_HIGH_BAND_RET);

    return iwm_send_cmd_pdu(sc, IWM_BT_CONFIG, 0, sizeof(bt_cmd),
        &bt_cmd);
}

void itlwm::wakeupOn(void *ident)
{
    XYLog("%s\n", __func__);
    if (fCommandGate == 0)
        return;
    else
        fCommandGate->commandWakeup(ident);
}

int itlwm::tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
    XYLog("%s %s\n", __func__, wmesg);
    if (fCommandGate == 0) {
        IOSleep(timo);
        return 0;
    }
    IOReturn ret;
    if (timo == 0) {
        ret = fCommandGate->runCommand(ident);
    } else {
        ret = fCommandGate->runCommand(ident, &timo);
    }
    if (ret == kIOReturnSuccess)
        return 0;
    else
        return 1;
}

IOReturn itlwm::tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    XYLog("%s\n", __func__);
    itlwm* dev = OSDynamicCast(itlwm, owner);
    if (dev == 0)
        return kIOReturnError;
    
    if (arg1 == 0) {
        if (dev->fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kMillisecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (dev->fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}
