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

#include "ItlIwm.hpp"

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlIwm, ItlHalService)

void ItlIwm::
detach(IOPCIDevice *device)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    ieee80211_ifdetach(ifp);
    taskq_destroy(systq);
    taskq_destroy(com.sc_nswq);
    releaseAll();
}

bool ItlIwm::
attach(IOPCIDevice *device)
{
    pci.pa_tag = device;
    pci.workloop = getMainWorkLoop();
    if (!iwm_attach(&com, &pci)) {
        detach(device);
        releaseAll();
        return false;
    }
    return true;
}

void ItlIwm::
free()
{
    XYLog("%s\n", __FUNCTION__);
    super::free();
}

void ItlIwm::
releaseAll()
{
    XYLog("%s\n", __FUNCTION__);
    pci_intr_handle *intrHandler = com.ih;
    if (com.sc_calib_to) {
        timeout_del(&com.sc_calib_to);
        timeout_free(&com.sc_calib_to);
    }
    if (com.sc_led_blink_to) {
        timeout_del(&com.sc_led_blink_to);
        timeout_free(&com.sc_led_blink_to);
    }
    if (intrHandler) {
        if (intrHandler->intr && intrHandler->workloop) {
//            intrHandler->intr->disable();
            intrHandler->workloop->removeEventSource(intrHandler->intr);
            intrHandler->intr->release();
        }
        intrHandler->intr = NULL;
        intrHandler->workloop = NULL;
        intrHandler->arg = NULL;
        intrHandler->dev = NULL;
        intrHandler->func = NULL;
        intrHandler->release();
        com.ih = NULL;
    }
    pci.pa_tag = NULL;
    pci.workloop = NULL;
}

IOReturn ItlIwm::
enable(IONetworkInterface *netif)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    ifp->if_flags |= IFF_UP;
    iwm_activate(&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn ItlIwm::
disable(IONetworkInterface *netif)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    ifp->if_flags &= ~IFF_UP;
    iwm_activate(&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

struct ieee80211com *ItlIwm::
get80211Controller()
{
    return &com.sc_ic;
}

ItlDriverInfo *ItlIwm::
getDriverInfo()
{
    return this;
}

ItlDriverController *ItlIwm::
getDriverController()
{
    return this;
}

void ItlIwm::
clearScanningFlags()
{
    com.sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
}

IOReturn ItlIwm::
setMulticastList(IOEthernetAddress *addr, int count)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct iwm_mcast_filter_cmd *cmd;
    int len;
    uint8_t addr_count;
    int err;
    
    if (ic->ic_state != IEEE80211_S_RUN || ic->ic_bss == NULL)
        return kIOReturnError;
    addr_count = count;
    if (count > IWM_MAX_MCAST_FILTERING_ADDRESSES)
        addr_count = 0;
    if (addr == NULL)
        addr_count = 0;
    len = roundup(sizeof(struct iwm_mcast_filter_cmd) + addr_count * ETHER_ADDR_LEN, 4);
    XYLog("%s multicast count=%d bssid=%s\n", __FUNCTION__, count, ether_sprintf(ic->ic_bss->ni_bssid));
    cmd = (struct iwm_mcast_filter_cmd *)malloc(len, 0, 0);
    if (!cmd)
        return kIOReturnError;
    cmd->pass_all = addr_count == 0;
    cmd->count = addr_count;
    cmd->port_id = 0;
    IEEE80211_ADDR_COPY(cmd->bssid, ic->ic_bss->ni_bssid);
    if (addr_count > 0)
        memcpy(cmd->addr_list,
               addr->bytes, ETHER_ADDR_LEN * cmd->count);
    err = iwm_send_cmd_pdu(&com, IWM_MCAST_FILTER_CMD, IWM_CMD_ASYNC, len,
                     cmd);
    ::free(cmd);
    return err ? kIOReturnError : kIOReturnSuccess;
}

const char *ItlIwm::
getFirmwareVersion()
{
    return com.sc_fwver;
}

const char *ItlIwm::
getFirmwareName()
{
    return com.sc_fwname;
}

UInt32 ItlIwm::
supportedFeatures()
{
    return 0;
}

const char *ItlIwm::
getFirmwareCountryCode()
{
    return com.sc_fw_mcc;
}

uint32_t ItlIwm::
getTxQueueSize()
{
    return IWM_TX_RING_COUNT;
}

int16_t ItlIwm::
getBSSNoise()
{
    return com.sc_noise;
}

bool ItlIwm::
is5GBandSupport()
{
    return com.sc_nvm.sku_cap_band_52GHz_enable;
}

int ItlIwm::
getTxNSS()
{
    return !com.sc_nvm.sku_cap_mimo_disable ? (iwm_mimo_enabled(&com) ? 2 : 1) : 1;
}
