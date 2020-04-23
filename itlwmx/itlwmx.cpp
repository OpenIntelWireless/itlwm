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

#include "itlwmx.hpp"
#include "types.h"
#include "kernel.h"

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/ethernet.h>

#define super IOEthernetController
OSDefineMetaClassAndStructors(itlwmx, IOEthernetController)
OSDefineMetaClassAndStructors(CTimeout, OSObject)

IOWorkLoop *_fWorkloop;
IOCommandGate *_fCommandGate;

bool itlwmx::init(OSDictionary *properties)
{
    super::init(properties);
    _fwLoadLock = IOLockAlloc();
    return true;
}

IOService* itlwmx::probe(IOService *provider, SInt32 *score)
{
    super::probe(provider, score);
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return NULL;
    }
    return iwx_match(device) == 0?NULL:this;
}

bool itlwmx::configureInterface(IONetworkInterface *netif) {
    IONetworkData *nd;
    
    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }
    
    nd = netif->getNetworkData(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    
    com.sc_ic.ic_ac.ac_if.netStat = fpNetStats;
    
    return true;
}

bool itlwmx::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;
    
    OSDictionary *mediumDict = OSDictionary::withCapacity(1);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }
    
    medium = IONetworkMedium::medium(kIOMediumEthernetAuto, 1024 * 1000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();  // 'mediumDict' holds a ref now.
    if (primary) {
        *primary = medium;
    }
    
    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }
    
    // Per comment for 'publishMediumDictionary' in NetworkController.h, the
    // medium dictionary is copied and may be safely relseased after the call.
    mediumDict->release();
    return result;
}

bool itlwmx::start(IOService *provider)
{
    ifnet *ifp;
    
    if (!super::start(provider)) {
        return false;
    }
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device) {
        return false;
    }
    device->setBusMasterEnable(true);
    device->setIOEnable(true);
    device->setMemoryEnable(true);
    device->configWrite8(0x41, 0);
    _fWorkloop = getWorkLoop();
    irqWorkloop = _fWorkloop;
    fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)tsleepHandler);
    _fCommandGate = fCommandGate;
    if (fCommandGate == 0) {
        XYLog("No command gate!!\n");
        return false;
    }
    fCommandGate->retain();
    _fWorkloop->addEventSource(fCommandGate);
    const IONetworkMedium *primaryMedium;
    if (!createMediumTables(&primaryMedium) ||
        !setCurrentMedium(primaryMedium)) {
        return false;
    }
    pci.workloop = irqWorkloop;
    pci.pa_tag = device;
    if (!iwx_attach(&com, &pci)) {
        return false;
    }
    ifp = &com.sc_ic.ic_ac.ac_if;
    if (!attachInterface((IONetworkInterface **)&com.sc_ic.ic_ac.ac_if.iface)) {
        XYLog("attach to interface fail\n");
        return false;
    }
    setLinkStatus(kIONetworkLinkValid);
    registerService();
    return true;
}

IOReturn itlwmx::getPacketFilters(const OSSymbol *group, UInt32 *filters) const {
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup) {
        *filters = 0;
    } else {
        rtn = super::getPacketFilters(group, filters);
    }
    
    return rtn;
}

IOReturn itlwmx::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

void itlwmx::stop(IOService *provider)
{
    XYLog("%s\n", __FUNCTION__);
    struct ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    IOEthernetInterface *inf = ifp->iface;
    pci_intr_handle *handle = com.ih;
    
    super::stop(provider);
    setLinkStatus(kIONetworkLinkValid);
    if (inf) {
        //        taskq_destroy(systq);
        //        taskq_destroy(com.sc_nswq);
        ieee80211_ifdetach(ifp);
        detachInterface(inf);
        OSSafeReleaseNULL(inf);
    }
    if (handle && _fWorkloop) {
        handle->dev->release();
        handle->dev = NULL;
        handle->func = NULL;
        handle->arg = NULL;
        handle->intr->disable();
        _fWorkloop->removeEventSource(handle->intr);
        handle->intr->release();
        handle->intr = NULL;
        OSSafeReleaseNULL(handle);
    }
    if (fCommandGate && _fWorkloop) {
        fCommandGate->disable();
        _fWorkloop->removeEventSource(fCommandGate);
        fCommandGate->release();
        fCommandGate = NULL;
    }
    if (_fWorkloop) {
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
}

void itlwmx::free()
{
    XYLog("%s\n", __FUNCTION__);
    if (_fwLoadLock) {
        IOLockFree(_fwLoadLock);
        _fwLoadLock = NULL;
    }
    super::free();
}

ieee80211_wpaparams wpa;
ieee80211_wpapsk psk;
ieee80211_nwkey nwkey;
ieee80211_join join;
const char *ssid_name = "ssdt";
const char *ssid_pwd = "zxyssdt112233";

#include "sha1.h"

IOReturn itlwmx::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    struct ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    super::enable(netif);
    fCommandGate->enable();
    memset(&wpa, 0, sizeof(ieee80211_wpaparams));
    wpa.i_enabled = 1;
    wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
    wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
    wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    wpa.i_akms = IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_PSK | IEEE80211_WPA_AKM_SHA256_8021X;
    memcpy(wpa.i_name, "zxy", strlen("zxy"));
    memset(&psk, 0, sizeof(ieee80211_wpapsk));
    memcpy(psk.i_name, "zxy", strlen("zxy"));
    psk.i_enabled = 1;
    pbkdf2_sha1(ssid_pwd, (const uint8_t*)ssid_name, strlen(ssid_name),
                4096, psk.i_psk , 32);
    memset(&nwkey, 0, sizeof(ieee80211_nwkey));
    nwkey.i_wepon = 0;
    nwkey.i_defkid = 0;
    memset(&join, 0, sizeof(ieee80211_join));
    join.i_wpaparams = wpa;
    join.i_wpapsk = psk;
    join.i_flags = IEEE80211_JOIN_WPAPSK | IEEE80211_JOIN_ANY | IEEE80211_JOIN_WPA | IEEE80211_JOIN_8021X;
    join.i_nwkey = nwkey;
    join.i_len = strlen(ssid_name);
    memcpy(join.i_nwid, ssid_name, join.i_len);
    ifp->if_flags |= IFF_UP;
    iwx_activate(&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn itlwmx::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    struct ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    super::disable(netif);
    wakeupOn(&com);
    iwx_activate(&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

IOReturn itlwmx::getHardwareAddress(IOEthernetAddress *addrP) {
    addrP->bytes[0] = com.sc_nvm.hw_addr[0];
    addrP->bytes[1] = com.sc_nvm.hw_addr[1];
    addrP->bytes[2] = com.sc_nvm.hw_addr[2];
    addrP->bytes[3] = com.sc_nvm.hw_addr[3];
    addrP->bytes[4] = com.sc_nvm.hw_addr[4];
    addrP->bytes[5] = com.sc_nvm.hw_addr[5];
    XYLog("%s %02x, %02x, %02x, %02x, %02x, %02x\n", __FUNCTION__, addrP->bytes[0], addrP->bytes[1], addrP->bytes[2], addrP->bytes[3], addrP->bytes[4], addrP->bytes[5]);
    XYLog("%s %02x, %02x, %02x, %02x, %02x, %02x\n", __FUNCTION__, com.sc_ic.ic_myaddr[0], com.sc_ic.ic_myaddr[1], com.sc_ic.ic_myaddr[2], com.sc_ic.ic_myaddr[3], com.sc_ic.ic_myaddr[4], com.sc_ic.ic_myaddr[5]);
    return kIOReturnSuccess;
}

UInt32 itlwmx::outputPacket(mbuf_t m, void *param)
{
    XYLog("%s\n", __FUNCTION__);
    ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    
    if (com.sc_ic.ic_state != IEEE80211_S_RUN || ifp == NULL || ifp->if_snd == NULL) {
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    ifp->if_snd->lockEnqueue(m);
    (*ifp->if_start)(ifp);
    
    return kIOReturnOutputSuccess;
}

UInt32 itlwmx::getFeatures() const
{
    UInt32 features = (kIONetworkFeatureMultiPages | kIONetworkFeatureHardwareVlan);
    features |= kIONetworkFeatureTSOIPv4;
    features |= kIONetworkFeatureTSOIPv6;
    return features;
}

IOReturn itlwmx::setPromiscuousMode(IOEnetPromiscuousMode mode) {
    return kIOReturnSuccess;
}

IOReturn itlwmx::setMulticastMode(IOEnetMulticastMode mode) {
    return kIOReturnSuccess;
}

IOReturn itlwmx::setMulticastList(IOEthernetAddress* addr, UInt32 len) {
    return kIOReturnSuccess;
}

void* itlwmx::
malloc(vm_size_t len, int type, int how)
{
    void* addr = IOMalloc(len + sizeof(vm_size_t));
    if (addr == NULL) {
        return NULL;
    }
    *((vm_size_t*) addr) = len;
    void *buf = (void*)((uint8_t*)addr + sizeof(vm_size_t));
    if (how & M_ZERO) {
        bzero(buf, len);
    }
    return buf;
}

#define MUL_NO_OVERFLOW    (1UL << (sizeof(size_t) * 4))

#define    M_CANFAIL    0x0004
void *itlwmx::
mallocarray(size_t nmemb, size_t size, int type, int flags)
{
    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        nmemb > 0 && SIZE_MAX / nmemb < size) {
        if (flags & M_CANFAIL)
            return (NULL);
        panic("mallocarray: overflow %zu * %zu", nmemb, size);
    }
    return (malloc(size * nmemb, type, flags));
}

void itlwmx::
free(void* addr)
{
    if (addr == NULL) {
        return;
    }
    void* actual_addr = (void*)((uint8_t*)addr - sizeof(vm_size_t));
    vm_size_t len = *((vm_size_t*) actual_addr);
    IOFree(actual_addr, len + sizeof(vm_size_t));
}

void itlwmx::wakeupOn(void *ident)
{
    XYLog("%s\n", __FUNCTION__);
    if (fCommandGate == 0)
        return;
    else
        fCommandGate->commandWakeup(ident);
}

int itlwmx::tsleep_nsec(void *ident, int priority, const char *wmesg, int timo)
{
    XYLog("%s %s\n", __FUNCTION__, wmesg);
    IOReturn ret;
    if (fCommandGate == 0) {
        IOSleep(timo);
        return 0;
    }
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

IOReturn itlwmx::tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    itlwmx* dev = OSDynamicCast(itlwmx, owner);
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
