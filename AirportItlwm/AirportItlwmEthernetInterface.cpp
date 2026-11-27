//
//  AirportItlwmEthernetInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "AirportItlwmEthernetInterface.hpp"

#include <sys/_if_ether.h>
#include <net80211/ieee80211_var.h>
#ifdef AIRPORT_WCL
#include <IOKit/IOCommandGate.h>
extern IOCommandGate *_fCommandGate;
#endif

#define super IOEthernetInterface
OSDefineMetaClassAndStructors(AirportItlwmEthernetInterface, IOEthernetInterface);

bool AirportItlwmEthernetInterface::
initWithSkywalkInterfaceAndProvider(IONetworkController *controller, IO80211SkywalkInterface *interface)
{
    bool ret = super::init(controller);
    if (ret)
        this->interface = interface;
    this->isAttach = false;
    return ret;
}

#ifdef AIRPORT_WCL
IOReturn AirportItlwmEthernetInterface::prepareBSDGated(OSObject *, void *arg0, void *, void *, void *)
{
    auto self = static_cast<AirportItlwmEthernetInterface *>(arg0);
    auto controller = OSDynamicCast(IO80211Controller, self->getController());
    auto queue = controller ? controller->getWorkQueue() : nullptr;
    if (!queue || !queue->inGate() || queue->onThread()) {
        return kIOReturnNotPermitted;
    }
    return self->interface->prepareBSDInterface(self->getIfnet(), 0);
}
#endif

IOReturn AirportItlwmEthernetInterface::
attachToDataLinkLayer( IOOptionBits options, void *parameter )
{
    XYLog("%s\n", __FUNCTION__);
    char infName[IFNAMSIZ];
#ifdef AIRPORT_WCL
    if (!setInterfaceSubType(3)) {
        return kIOReturnNotReady;
    }
#endif
    IOReturn ret = super::attachToDataLinkLayer(options, parameter);
    if (ret == kIOReturnSuccess && interface) {
        UInt8 builtIn = 0;
        IOEthernetAddress addr;
        // The overloads that copy the value, so nothing is leaked per attach (audit ST03).
        interface->setProperty("built-in", &builtIn, sizeof(builtIn));
        snprintf(infName, sizeof(infName), "%s%u", ifnet_name(getIfnet()), ifnet_unit(getIfnet()));
        interface->setProperty("IOInterfaceName", infName);
        interface->setProperty(kIOInterfaceUnit, (unsigned long long)ifnet_unit(getIfnet()), 8);
        interface->setProperty(kIOInterfaceNamePrefix, ifnet_name(getIfnet()));
        if (OSDynamicCast(IOEthernetController, getController())->getHardwareAddress(&addr) == kIOReturnSuccess)
            setProperty(kIOMACAddress,  (void *) &addr,
                        kIOEthernetAddressSize);
#ifdef AIRPORT_WCL
        ret = _fCommandGate ? _fCommandGate->runAction(prepareBSDGated, this) : kIOReturnNotReady;
        if (ret != kIOReturnSuccess) {
            super::detachFromDataLinkLayer(options, parameter);
            isAttach = false;
            return ret;
        }
        isAttach = true;
        interface->registerService();
#else
        interface->registerService();
        interface->prepareBSDInterface(getIfnet(), 0);
#endif
//        ret = bpf_attach(getIfnet(), DLT_RAW, 0x48, &AirportItlwmEthernetInterface::bpfOutputPacket, &AirportItlwmEthernetInterface::bpfTap);
    }
#ifdef AIRPORT_WCL
    isAttach = ret == kIOReturnSuccess;
#else
    isAttach = true;
#endif
    return ret;
}

void AirportItlwmEthernetInterface::
detachFromDataLinkLayer(IOOptionBits options, void *parameter)
{
    super::detachFromDataLinkLayer(options, parameter);
    isAttach = false;
}

/**
 Add another hack to fake that the provider is IOSkywalkNetworkInterface, to avoid skywalkfamily instance cast panic.
 */
IOService *AirportItlwmEthernetInterface::
getProvider() const
{
    return isAttach ? this->interface : super::getProvider();
}

errno_t AirportItlwmEthernetInterface::
bpfOutputPacket(ifnet_t interface, u_int32_t data_link_type, mbuf_t packet)
{
    XYLog("%s data_link_type: %d\n", __FUNCTION__, data_link_type);
    AirportItlwmEthernetInterface *networkInterface = (AirportItlwmEthernetInterface *)ifnet_softc(interface);
    return networkInterface->enqueueOutputPacket(packet);
}

errno_t AirportItlwmEthernetInterface::
bpfTap(ifnet_t interface, u_int32_t data_link_type, bpf_tap_mode direction)
{
    XYLog("%s data_link_type: %d direction: %d\n", __FUNCTION__, data_link_type, direction);
    return 0;
}

bool AirportItlwmEthernetInterface::
setLinkState(IO80211LinkState state)
{
    if (state == kIO80211NetworkLinkUp) {
        ifnet_set_flags(getIfnet(), ifnet_flags(getIfnet()) | (IFF_UP | IFF_RUNNING), (IFF_UP | IFF_RUNNING));
    } else {
        ifnet_set_flags(getIfnet(), ifnet_flags(getIfnet()) & ~(IFF_UP | IFF_RUNNING), 0);
    }
    return true;
}

extern const char* hexdump(uint8_t *buf, size_t len);

#ifdef AIRPORT_WCL
static mbuf_t normalizeInputPacket(mbuf_t packet, UInt32 length)
{
    const size_t packetLength = length ? length : mbuf_pkthdr_len(packet);
    if (!(mbuf_flags(packet) & MBUF_PKTHDR) || packetLength < ETHER_HDR_LEN) {
        mbuf_freem(packet);
        return NULL;
    }
    if (!mbuf_next(packet) && mbuf_len(packet) >= packetLength)
        return packet;

    unsigned int maxChunks = 1;
    mbuf_t linear = NULL;
    if (mbuf_allocpacket(MBUF_DONTWAIT, packetLength + ETHER_ALIGN, &maxChunks, &linear)) {
        mbuf_freem(packet);
        return NULL;
    }
    UInt8 *data = static_cast<UInt8 *>(mbuf_data(linear)) + ETHER_ALIGN;
    if (mbuf_copydata(packet, 0, packetLength, data) ||
        mbuf_copy_pkthdr(linear, packet) ||
        mbuf_setdata(linear, data, packetLength)) {
        mbuf_freem(linear);
        mbuf_freem(packet);
        return NULL;
    }
    mbuf_pkthdr_setlen(linear, packetLength);
    mbuf_pkthdr_setheader(linear, NULL);
    mbuf_freem(packet);
    return linear;
}
#endif

UInt32 AirportItlwmEthernetInterface::
inputPacket(mbuf_t packet, UInt32 length, IOOptionBits options, void *param)
{
#ifdef AIRPORT_WCL
    if (!packet)
        return 0;
    if (!getIfnet()) {
        mbuf_freem(packet);
        return 0;
    }
    const bool directInput = param == packet;
    packet = normalizeInputPacket(packet, length);
    if (!packet) {
        IONetworkData *data = getParameter(kIONetworkStatsKey);
        IONetworkStats *stats = data ? (IONetworkStats *)data->getBuffer() : NULL;
        if (stats)
            stats->inputErrors++;
        return 0;
    }
    if (directInput)
        param = packet;
#endif
    // The non-WCL (Sonoma) build used to log every received EAPOL frame as hex, handshake and encrypted
    // group key included (audit D04, HL02). Removed.
    return IOEthernetInterface::inputPacket(packet, length, options, param);
}
