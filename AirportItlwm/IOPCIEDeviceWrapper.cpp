//
//  IOPCIEDeviceWrapper.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "IOPCIEDeviceWrapper.hpp"
#include "Apple80211.h"

#include "ItlIwm.hpp"
#include "ItlIwx.hpp"
#include "ItlIwn.hpp"

#define super IOService
OSDefineMetaClassAndStructors(IOPCIEDeviceWrapper, IOService);

#define  PCI_MSI_FLAGS        2    /* Message Control */
#define  PCI_CAP_ID_MSI        0x05    /* Message Signalled Interrupts */
#define  PCI_MSIX_FLAGS        2    /* Message Control */
#define  PCI_CAP_ID_MSIX    0x11    /* MSI-X */
#define  PCI_MSIX_FLAGS_ENABLE    0x8000    /* MSI-X enable */
#define  PCI_MSI_FLAGS_ENABLE    0x0001    /* MSI feature enabled */

static IOPMPowerState powerStateArray[2] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

static void pciMsiSetEnable(IOPCIDevice *device, UInt8 msiCap, int enable)
{
    UInt16 control;

    control = device->configRead16(msiCap + PCI_MSI_FLAGS);
    control &= ~PCI_MSI_FLAGS_ENABLE;
    if (enable)
        control |= PCI_MSI_FLAGS_ENABLE;
    device->configWrite16(msiCap + PCI_MSI_FLAGS, control);
}

static void pciMsiXClearAndSet(IOPCIDevice *device, UInt8 msixCap, UInt16 clear, UInt16 set)
{
    UInt16 ctrl;

    ctrl = device->configRead16(msixCap + PCI_MSIX_FLAGS);
    ctrl &= ~clear;
    ctrl |= set;
    device->configWrite16(msixCap + PCI_MSIX_FLAGS, ctrl);
}

extern IOWorkLoop *_fWorkloop;

IOWorkLoop *IOPCIEDeviceWrapper::getWorkLoop() const
{
    return _fWorkloop;
}

// The driver keeps its work loop, command gate and AWDL state in globals, so it can only run one
// card. A second supported Intel card is left alone instead of overwriting the first one's state.
static volatile UInt32 gCardClaimed = 0;

IOService* IOPCIEDeviceWrapper::
probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::probe(provider, score);
    IOPCIDevice* device = OSDynamicCast(IOPCIDevice, provider);
    if (!device)
        return NULL;
    const int kind = ItlIwx::iwx_match(device) ? 1 : ItlIwm::iwm_match(device) ? 2 :
        ItlIwn::iwn_match(device) ? 3 : 0;
    if (!kind)
        return NULL;
    XYLog("%s Found\n", __FUNCTION__);
    if (!claimedCard) {
        if (!OSCompareAndSwap(0, 1, &gCardClaimed)) {
            XYLog("%s: another Intel Wi-Fi card is already in use; this driver runs one card only\n", __FUNCTION__);
            return NULL;
        }
        claimedCard = true;
    }
    // probe can run more than once; keep the HAL already made for this device.
    halKind = kind;
    if (!fHalService)
        fHalService = newHal(kind);
    // findPCICapability returns the capability register's value (0 when absent) and writes the
    // offset through its pointer. 0.4.0 and 0.4.1 used the value as the offset: the low byte is the
    // capability ID, so they wrote config offsets 0x13 and 0x07 instead of the MSI-X and MSI control
    // words, never enabled MSI, and the driver failed to start on some machines (#14, #16).
    UInt8 msixCap = 0, msiCap = 0;
    if (!device->findPCICapability(PCI_CAP_ID_MSIX, &msixCap))
        msixCap = 0;
    if (!device->findPCICapability(PCI_CAP_ID_MSI, &msiCap))
        msiCap = 0;
    if (!fHalService || (!msiCap && !msixCap)) {
        XYLog("%s %s\n", __FUNCTION__, fHalService ? "No MSI cap" : "no memory");
        OSSafeReleaseNULL(fHalService);
        claimedCard = false;
        OSCompareAndSwap(1, 0, &gCardClaimed);
        return NULL;
    }
    if (msixCap)
        pciMsiXClearAndSet(device, msixCap, PCI_MSIX_FLAGS_ENABLE, 0);
    if (msiCap)
        pciMsiSetEnable(device, msiCap, 1);
    this->pciNub = device;
    return this;
}

ItlHalService *IOPCIEDeviceWrapper::newHal(int kind)
{
    return kind == 1 ? static_cast<ItlHalService *>(new ItlIwx) :
        kind == 2 ? static_cast<ItlHalService *>(new ItlIwm) : static_cast<ItlHalService *>(new ItlIwn);
}

ItlHalService *IOPCIEDeviceWrapper::halForStart()
{
    // A HAL whose controller stopped (or failed to start) is shut down: its detach left the device
    // quiesced and its DMA state gone, so it starts again only as a new object (audit P-R02).
    if (fHalService && fHalService->isShutDown()) {
        OSSafeReleaseNULL(fHalService);
        fHalService = newHal(halKind);
    }
    return fHalService;
}

void IOPCIEDeviceWrapper::free()
{
    OSSafeReleaseNULL(fHalService);
    if (claimedCard) {
        claimedCard = false;
        OSCompareAndSwap(1, 0, &gCardClaimed);
    }
    super::free();
}

bool IOPCIEDeviceWrapper::
start(IOService *provider)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    _fWorkloop = IO80211WorkQueue::workQueue();
    if (!super::start(provider)) {
        return false;
    }
    IOLog("%s::super start succeed\n", getName());
    UInt8 builtIn = 0;
    if (OSData *builtInData = OSData::withBytes(&builtIn, sizeof(builtIn))) {   // released (audit P-A07)
        setProperty("built-in", builtInData);
        builtInData->release();
    }
    PMinit();
    registerPowerDriver(this, powerStateArray, 2);
    provider->joinPMtree(this);
    registerService();
    return true;
}

void IOPCIEDeviceWrapper::
stop(IOService *provider)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    PMstop();
    super::stop(provider);
}

IOReturn IOPCIEDeviceWrapper::
setPowerState(unsigned long powerStateOrdinal, IOService *whatDevice)
{
    return IOPMAckImplied;
}
