//
//  utils.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"
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
    free(addr);
}

int itlwm::
iwm_send_bt_init_conf(struct iwm_softc *sc)
{
    struct iwm_bt_coex_cmd bt_cmd;

    bt_cmd.mode = htole32(IWM_BT_COEX_WIFI);
    bt_cmd.enabled_modules = htole32(IWM_BT_COEX_HIGH_BAND_RET);

    return iwm_send_cmd_pdu(sc, IWM_BT_CONFIG, 0, sizeof(bt_cmd),
        &bt_cmd);
}
