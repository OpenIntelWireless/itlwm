/*
 * Copyright (c) 1998-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _IOETHERNETCONTROLLER_H
#define _IOETHERNETCONTROLLER_H

#include "IONetworkController.h"

/*! @defined kIOEthernetControllerClass
    @abstract kIOEthernetControllerClass is the name of the
        IOEthernetController class. */

#define kIOEthernetControllerClass        "IOEthernetController"

/*! @defined kIOEthernetAddressSize
    @abstract The number of bytes in an Ethernet hardware address. */

#define kIOEthernetAddressSize            6

/*! @defined kIOEthernetMaxPacketSize
    @abstract The maximum size of an Ethernet packet, including
        the FCS bytes. */

#define kIOEthernetMaxPacketSize          1518

/*! @defined kIOEthernetMinPacketSize
    @abstract The minimum size of an Ethernet packet, including
        the FCS bytes. */

#define kIOEthernetMinPacketSize          64

/*! @defined kIOEthernetCRCSize
    @abstract The size in bytes of the 32-bit CRC value appended
        to the end of each Ethernet frame. */

#define kIOEthernetCRCSize                4

/*! @defined kIOEthernetWakeOnLANFilterGroup
    @abstract kIOEthernetWakeOnLANFilterGroup describes the name assigned
        to the Ethernet Wake-On-LAN filter group. This group represents
        wake filters that are supported by the controller. */

#define kIOEthernetWakeOnLANFilterGroup   "IOEthernetWakeOnLANFilterGroup"

/*! @defined kIOEthernetDisabledWakeOnLANFilterGroup
    @abstract kIOEthernetDisabledWakeOnLANFilterGroup describes the name
        assigned to the disabled Ethernet Wake-On-LAN filter group. This
        group represents wake filters that are currently disabled.
        Membership in this group is dynamic. */

#define kIOEthernetDisabledWakeOnLANFilterGroup \
        "IOEthernetDisabledWakeOnLANFilterGroup"

/*! @enum Wake On LAN Filters
    @abstract All filters in the Wake-on-LAN filter group.
    @discussion Each filter listed will respond to a network event that
        will trigger a system wake-up.
    @constant kIOEthernetWakeOnMagicPacket Reception of a Magic Packet.
    @constant kIOEthernetWakeOnPacketAddressMatch Reception of a packet
    which passes through any of the address filtering mechanisms based
    on its destination Ethernet address. This may include unicast,
    broadcast, or multicast addresses depending on the current state
    and setting of the corresponding packet filters. */

enum {
    kIOEthernetWakeOnMagicPacket         = 0x00000001,
    kIOEthernetWakeOnPacketAddressMatch  = 0x00000002
};

#ifdef KERNEL
#ifdef __cplusplus

struct IOEthernetAddress {
    UInt8 bytes[kIOEthernetAddressSize];
};

/*! @const gIOEthernetWakeOnLANFilterGroup
    @discussion gIOEthernetWakeOnLANFilterGroup is an OSSymbol object
    that contains the name of the Ethernet Wake-on-LAN filter group
    defined by kIOEthernetWakeOnLANFilterGroup. */

extern const OSSymbol * gIOEthernetWakeOnLANFilterGroup;

/*! @const gIOEthernetDisabledWakeOnLANFilterGroup
    @discussion gIOEthernetDisabledWakeOnLANFilterGroup is an OSSymbol object
    that contains the name of the disabled Ethernet Wake-on-LAN filter group
    defined by kIOEthernetDisabledWakeOnLANFilterGroup. */

extern const OSSymbol * gIOEthernetDisabledWakeOnLANFilterGroup;


/*! @enum AVB Time Sync Support
    @abstract The support that the controller has for Time Sync timestamping.
    @discussion A controller can support ingress and egress timestamping of time sync packets
        in a number of ways.
    @const kIOEthernetControllerAVBTimeSyncSupportNone Controller does not support sending or
        receiving packets with ingress and egress timestamping
    @const kIOEthernetControllerAVBTimeSyncSupportHardware Controller supports sending and
        receiving packets with ingress and egress timestamping and the timestamping is done in hardware
    @const kIOEthernetControllerAVBTimeSyncSupportInterrupt Controller supports sending and receiving
        packets with ingress and egress timestamping and the timestamping is done in the primary interrupt handler
    @const kIOEthernetControllerAVBTimeSyncSupportSoftware Controller supports sending and receiving
        packets with ingress and egress timestamping and the timestamping is done in software stack
        (secondary interrupt handler or higher)
*/
typedef enum
{
    kIOEthernetControllerAVBTimeSyncSupportNone,
    kIOEthernetControllerAVBTimeSyncSupportHardware,
    kIOEthernetControllerAVBTimeSyncSupportInterrupt,
    kIOEthernetControllerAVBTimeSyncSupportSoftware,
} IOEthernetControllerAVBTimeSyncSupport;


/*! @enum Controller AVB States
    @abstract The state the AVB support is in.
    @discussion A controller can be in one of 4 states depending on the capabilities required by the AVB stack.
    @const kIOEthernetControllerAVBStateDisabled No AVB streaming services or gPTP can run
    @const kIOEthernetControllerAVBStateActivated No AVB streaming services and no gPTP but they can be
        enabled, no media restrictions
    @const kIOEthernetControllerAVBStateTimeSyncEnabled No AVB streaming services, time sync hardware
        enabled so that gPTP can run, no media restrictions
    @const kIOEthernetControllerAVBStateAVBEnabled AVB streams can run, media restrictions are in place
*/
typedef enum
{
    kIOEthernetControllerAVBStateDisabled,
    kIOEthernetControllerAVBStateActivated,
    kIOEthernetControllerAVBStateTimeSyncEnabled,
    kIOEthernetControllerAVBStateAVBEnabled,
} IOEthernetControllerAVBState;

///Events to trigger changes of state
/*! @enum Controller AVB State Events
    @abstract Events to trigger the change in AVB state of the controller.
    @const kIOEthernetControllerAVBStateEventDisable Disable AVB support
    @const kIOEthernetControllerAVBStateEventEnable Enable AVB support
    @const kIOEthernetControllerAVBStateEventStartTimeSync Start using Time Sync services.
    @const kIOEthernetControllerAVBStateEventStopTimeSync Stop using Time Sync services.
    @const kIOEthernetControllerAVBStateEventStartStreaming Start using realtime streaming services.
    @const kIOEthernetControllerAVBStateEventStopStreaming Stop using realtime streaming services.
*/
typedef enum
{
    kIOEthernetControllerAVBStateEventDisable,
    kIOEthernetControllerAVBStateEventEnable,
    kIOEthernetControllerAVBStateEventStartTimeSync,
    kIOEthernetControllerAVBStateEventStopTimeSync,
    kIOEthernetControllerAVBStateEventStartStreaming,
    kIOEthernetControllerAVBStateEventStopStreaming,
} IOEthernetControllerAVBStateEvent;


class IOTimeSyncEthernetInterfaceAdapter;

/*! @class IOEthernetController
    @abstract Abstract superclass for Ethernet controllers.
    @discussion Ethernet controller drivers should subclass IOEthernetController, and implement
    or override the hardware specific methods to create an Ethernet driver.
    An interface object (an IOEthernetInterface instance) must be
    instantiated by the driver, through attachInterface(), to connect
    the controller driver to the data link layer.
*/

class IOEthernetController : public IONetworkController
{
    OSDeclareAbstractStructors( IOEthernetController )

protected:
    struct IOECTSCallbackEntry;
    
    struct ExpansionData {
        IOEthernetControllerAVBTimeSyncSupport fTimeSyncSupport;
        bool fRealtimeMulticastAllowed;
        
        IOMapper *fAVBPacketMapper;
        
        uint32_t fNumberOfRealtimeTransmitQueues;
        uint64_t *fTransmitQueuePacketLatency;
        uint64_t *fTransmitQueuePrefetchDelay;
        
        uint32_t fNumberOfRealtimeReceiveQueues;
        
        IOEthernetControllerAVBState fAVBControllerState;
        int32_t fTimeSyncEnabled;
        int32_t fAVBEnabled;
        IOLock *fStateLock;
        OSArray *fStateChangeNotifiers;
        IOLock *fStateChangeNotifiersLock;
        
        OSArray *fTimeSyncReceiveHandlers;
        IOLock *fTimeSyncReceiveHandlersLock;
        OSArray *fTimeSyncTransmitHandlers;
        IOLock *fTimeSyncTransmitHandlersLock;
        uint32_t fNextTimeSyncTransmitCallbackID;
        bool fHasTimeSyncTransmitCallbackIDAvailable;
        
        struct IOECTSCallbackEntry *fTimeSyncTransmitCallbackQueue;
        IOLock *fTimeSyncTransmitCallbackQueueLock;
        struct IOECTSCallbackEntry *fTimeSyncReceiveCallbackQueue;
        IOLock *fTimeSyncReceiveCallbackQueueLock;
        
        bool fTimeSyncCallbackThreadShouldKeepRunning;
        bool fTimeSyncCallbackThreadIsRunning;
        thread_t fTimeSyncCallbackThread;
        semaphore_t fTimeSyncCallbackStartSemaphore;
        semaphore_t fTimeSyncCallbackStopSemaphore;
        semaphore_t fTimeSyncCallbackQueueSemaphore;
        uint64_t fTimeSyncCallbackTimeoutTime;
        
        bool fgPTPPresent;
    };
    
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *  _reserved;


public:

/*! @function initialize
    @abstract IOEthernetController class initializer.
    @discussion Creates global OSSymbol objects that are used as keys. */

    static void initialize();

/*! @function init
    @abstract Initializes an IOEthernetController object.
    @param properties A dictionary object containing a property table
        associated with this instance.
    @result Returns true on success, false otherwise.
*/

    virtual bool init(OSDictionary * properties) APPLE_KEXT_OVERRIDE;

/*! @function getPacketFilters
    @abstract Gets the set of packet filters supported by the Ethernet
    controller in the given filter group.
    @discussion The default implementation of the abstract method inherited
    from IONetworkController. When the filter group specified is
    gIONetworkFilterGroup, then this method will return a value formed by
    a bitwise OR of kIOPacketFilterUnicast, kIOPacketFilterBroadcast,
    kIOPacketFilterMulticast, kIOPacketFilterPromiscuous. Otherwise, the
    return value will be set to zero (0). Subclasses must override this
    method if their filtering capability differs from what is reported by
    this default implementation. This method is called from the workloop
    context, and the result is published to the I/O Kit Registry.
    @param group The name of the filter group.
    @param filters Pointer to the mask of supported filters returned by
        this method.
    @result Returns kIOReturnSuccess. Drivers that override this
    method must return kIOReturnSuccess to indicate success, or an error
    return code otherwise.
*/

    virtual IOReturn getPacketFilters(const OSSymbol * group,
                                      UInt32 *         filters) const APPLE_KEXT_OVERRIDE;

/*! @function enablePacketFilter
    @abstract Enables one of the supported packet filters from the
    given filter group.
    @discussion The default implementation of the abstract method inherited
    from IONetworkController. This method will call setMulticastMode() or
    setPromiscuousMode() when the multicast or the promiscuous filter is to be
    enabled. Requests to disable the Unicast or Broadcast filters are handled
    silently, without informing the subclass. Subclasses can override this
    method to change this default behavior, or to extend it to handle
    additional filter types or filter groups. This method call is synchronized
    by the workloop's gate.
    @param group The name of the filter group containing the filter to be
    enabled.
    @param aFilter The filter to enable.
    @param enabledFilters All filters currently enabled by the client.
    @param options Optional flags for the enable request.
    @result Returns the value returned by setMulticastMode() or setPromiscuousMode() if
    either of those two methods are called. Returns kIOReturnSuccess if the filter
    specified is kIOPacketFilterUnicast or kIOPacketFilterBroadcast.
    Returns kIOReturnUnsupported if the filter group specified is not
    gIONetworkFilterGroup.
*/

    virtual IOReturn enablePacketFilter(const OSSymbol * group,
                                        UInt32           aFilter,
                                        UInt32           enabledFilters,
                                        IOOptionBits     options = 0) APPLE_KEXT_OVERRIDE;

/*! @function disablePacketFilter
    @abstract Disables a packet filter that is currently enabled from the
    given filter group.
    @discussion The default implementation of the abstract method inherited
    from IONetworkController. This method will call setMulticastMode() or
    setPromiscuousMode() when the multicast or the promiscuous filter is to be
    disabled. Requests to disable the Unicast or Broadcast filters are handled
    silently, without informing the subclass. Subclasses can override this
    method to change this default behavior, or to extend it to handle
    additional filter types or filter groups. This method call is synchronized
    by the workloop's gate.
    @param group The name of the filter group containing the filter to be
    disabled.
    @param aFilter The filter to disable.
    @param enabledFilters All filters currently enabled by the client.
    @param options Optional flags for the disable request.
    @result Returns the value returned by setMulticastMode() or setPromiscuousMode() if
    either of those two methods are called. Returns kIOReturnSuccess if the filter
    specified is kIOPacketFilterUnicast or kIOPacketFilterBroadcast.
    Returns kIOReturnUnsupported if the filter group specified is not
    gIONetworkFilterGroup.
*/

    virtual IOReturn disablePacketFilter(const OSSymbol * group,
                                         UInt32           aFilter,
                                         UInt32           enabledFilters,
                                         IOOptionBits     options = 0) APPLE_KEXT_OVERRIDE;

/*! @function getHardwareAddress
    @abstract Gets the Ethernet controller's station address.
    @discussion The default implementation of the abstract method inherited
    from IONetworkController. This method will call the overloaded form
    IOEthernetController::getHardwareAddress() that subclasses are expected
    to override.
    @param addr The buffer where the controller's hardware address should
           be written.
    @param inOutAddrBytes The size of the address buffer provided by the
           client, and replaced by this method with the actual size of
           the hardware address in bytes.
    @result Returns kIOReturnSuccess on success, or an error otherwise.
*/

    virtual IOReturn getHardwareAddress(void *   addr,
                                        UInt32 * inOutAddrBytes) APPLE_KEXT_OVERRIDE;

/*! @function setHardwareAddress
    @abstract Sets or changes the station address used by the Ethernet
    controller.
    @discussion The default implementation of the abstract method inherited
    from IONetworkController. This method will call the overloaded form
    IOEthernetController::setHardwareAddress() that subclasses are expected
    to override.
    @param addr The buffer containing the hardware address provided by
    the client.
    @param addrBytes The size of the address buffer provided by the
    client in bytes.
    @result Returns kIOReturnSuccess on success, or an error otherwise.
*/

    virtual IOReturn setHardwareAddress(const void * addr,
                                        UInt32       addrBytes) APPLE_KEXT_OVERRIDE;

/*! @function getMaxPacketSize
    @abstract Gets the maximum packet size supported by the Ethernet
        controller, including the frame header and FCS.
    @param maxSize Pointer to the return value.
    @result Returns kIOReturnSuccess on success, or an error code otherwise.
*/

    virtual IOReturn getMaxPacketSize(UInt32 * maxSize) const APPLE_KEXT_OVERRIDE;

/*! @function getMinPacketSize
    @abstract Gets the minimum packet size supported by the Ethernet
        controller, including the frame header and FCS.
    @param minSize Pointer to the return value.
    @result Returns kIOReturnSuccess on success, or an error code otherwise.
*/

    virtual IOReturn getMinPacketSize(UInt32 * minSize) const APPLE_KEXT_OVERRIDE;

/*! @function getPacketFilters
    @abstract Gets the set of packet filters supported by the Ethernet
    controller in the network filter group.
    @param filters Pointer to the return value containing a mask of
    supported filters.
    @result Returns kIOReturnSuccess. Drivers that override this
    method must return kIOReturnSuccess to indicate success, or an error
    return code otherwise.
*/

    virtual IOReturn getPacketFilters(UInt32 * filters) const;

/*! @function getHardwareAddress
    @abstract Gets the Ethernet controller's permanent station address.
    @discussion Ethernet drivers must implement this method, by reading the
    address from hardware and writing it to the buffer provided. This method
    is called from the workloop context.
    @param addrP Pointer to an IOEthernetAddress where the hardware address
    should be returned.
    @result Returns kIOReturnSuccess on success, or an error return code otherwise.
*/

    virtual IOReturn getHardwareAddress(IOEthernetAddress * addrP) = 0;

/*! @function setHardwareAddress
    @abstract Sets or changes the station address used by the Ethernet
        controller.
    @discussion This method is called in response to a client command to
    change the station address used by the Ethernet controller. Implementation
    of this method is optional. This method is called from the workloop context.
    @param addrP Pointer to an IOEthernetAddress containing the new station
    address.
    @result The default implementation will always return kIOReturnUnsupported.
    If overridden, drivers must return kIOReturnSuccess on success, or an error
    return code otherwise.
*/

    virtual IOReturn setHardwareAddress(const IOEthernetAddress * addrP);

/*! @function setMulticastMode
    @abstract Enables or disables multicast mode.
    @discussion Called by enablePacketFilter() or disablePacketFilter()
    when there is a change in the activation state of the multicast filter
    identified by kIOPacketFilterMulticast. This method is called from the
    workloop context.
    @param active True to enable multicast mode, false to disable it.
    @result Returns kIOReturnUnsupported. If overridden, drivers must return
    kIOReturnSuccess on success, or an error return code otherwise.
*/

    virtual IOReturn setMulticastMode(bool active);

/*! @function setMulticastList
    @abstract Sets the list of multicast addresses a multicast filter
    should use to match against the destination address of an incoming frame.
    @discussion This method sets the list of multicast addresses that the multicast filter
    should use to match against the destination address of an incoming frame.
    The frame should be accepted when a match occurs.  Called when the multicast group membership of an interface
    object is changed. Drivers that support kIOPacketFilterMulticast should
    override this method and update the hardware multicast filter using the
    list of Ethernet addresses provided. Perfect multicast filtering is
    preferred if supported by the hardware, in order to reduce the number of
    unwanted packets received. If the number of multicast addresses in the
    list exceeds what the hardware is capable of supporting, or if perfect
    filtering is not supported, then ideally the hardware should be programmed
    to perform imperfect filtering, through some form of hash filtering
    mechanism. Only as a last resort should the driver enable reception of
    all multicast packets to satisfy this request. This method is called
    from the workloop context, and only if the driver reports
    kIOPacketFilterMulticast support in getPacketFilters().
    @param addrs An array of Ethernet addresses. This argument must be
        ignored if the count argument is 0.
    @param count The number of Ethernet addresses in the list. This value
        will be zero when the list becomes empty.
    @result Returns kIOReturnUnsupported. Drivers must return kIOReturnSuccess to
    indicate success, or an error return code otherwise.
*/

    virtual IOReturn setMulticastList(IOEthernetAddress * addrs,
                                      UInt32              count);

/*! @function setPromiscuousMode
    @abstract Enables or disables promiscuous mode.
    @discussion Called by enablePacketFilter() or disablePacketFilter()
    when there is a change in the activation state of the promiscuous
    filter identified by kIOPacketFilterPromiscuous. This method is
    called from the workloop context.
    @param active True to enable promiscuous mode, false to disable it.
    @result Returns kIOReturnUnsupported. If overridden, drivers must return
    kIOReturnSuccess on success, or an error return code otherwise.
*/

    virtual IOReturn setPromiscuousMode(bool active);

/*! @function setWakeOnMagicPacket
    @abstract Enables or disables the wake on Magic Packet support.
    @discussion Called by enablePacketFilter() or disablePacketFilter()
    when there is a change in the activation state of the Wake-on-LAN
    filter identified by kIOEthernetWakeOnMagicPacket. This method is
    called from the workloop context.
    @param active True to enable support for system wake on reception
    of a Magic Packet, false to disable it.
    @result Returns kIOReturnUnsupported. If overridden, drivers must return
    kIOReturnSuccess on success, or an error return code otherwise.
*/

    virtual IOReturn setWakeOnMagicPacket(bool active);

protected:

/*! @function createInterface
    @abstract Creates an IOEthernetInterface object.
    @discussion This method allocates and returns a new IOEthernetInterface instance.
    A subclass of IONetworkController must implement this method and return
    a matching interface object. The implementation in IOEthernetController
    will return an IOEthernetInterface object. Subclasses of
    IOEthernetController, such as Ethernet controller drivers, will have
    little reason to override this implementation.
    @result Returns a newly allocated and initialized IOEthernetInterface object.
*/

    virtual IONetworkInterface * createInterface() APPLE_KEXT_OVERRIDE;

/*! @function free
    @abstract Frees the IOEthernetController instance.
    @discussion This method releases resources, and is
    then followed by a call to super::free(). */

    virtual void free() APPLE_KEXT_OVERRIDE;

/*! @function publishProperties
    @abstract Publishes Ethernet controller properties and capabilities.
    @discussion This method publishes Ethernet controller properties to the property
    table. For instance, getHardwareAddress() is called to fetch the
    hardware address, and the address is then published to the property
    table. This method call is synchronized by the workloop's gate,
    and must never be called directly by subclasses.
    @result Returns true if all properties and capabilities were discovered,
    and published successfully, false otherwise. Returning false will
    prevent client objects from attaching to the Ethernet controller
    since a property that a client relies upon may be missing.
*/

    virtual bool publishProperties() APPLE_KEXT_OVERRIDE;

    OSMetaClassDeclareReservedUsed( IOEthernetController,  0);

    /*! @function getVlanTagDemand
        @abstract Fetch the demand for hardware vlan tag stuffing
        for the given packet before it is transmitted on the network.
        @discussion A network controller that can insert 802.1Q vlan tags for output
        packets must call this method to obtain vlan tag information that it must
        insert into the given output packet.
        @param m A mbuf containing a packet that may require vlan tag stuffing.
        @param vlanTag After calling, the low order 16 bits contain the 802.1Q priority and
        vlan ID tag in host order.  The hi-order 16 bits are currently unused and should be ignored.
        @result true if vlanTag has been set and should be used.
        false if no vlan tag stuffing is required for this packet. */

    virtual bool getVlanTagDemand(mbuf_t m, UInt32 *vlanTag);

    OSMetaClassDeclareReservedUsed( IOEthernetController,  1);

    /*! @function setVlanTag
        @abstract Encode a received packet with the vlan tag result reported
        by the hardware.
        @discussion A network controller that can strip 802.1Q vlan tag information for a
        received packet should call this method to encode the result on the
        packet, before passing it up towards the protocol stacks.
        @param m A mbuf containing a packet that has had its 802.1q vlan tag stripped by
        the hardware.
        @param vlanTag A value in host order that contains the 802.1q vlan tag and priority
        in the low order 16 bits.  The hi order word is currently unused and should be set to 0. */

    virtual void setVlanTag(mbuf_t m, UInt32 vlanTag);
    
    
    
    
public:
    
    /*! @struct IOEthernetControllerAVBSupport
        @abstract Group of capabilities for the AVB/TSN support of the driver and hardware.
        @discussion Structure containing the AVB/TSN capabilities of the controller.
        @field timeSyncSupport The type of time sync timestamping support the driver provides.
        @field numberOfRealtimeTransmitQueues The number of hardware queues available for AVB
            traffic transmission. These are queues which support launch timestamps.
        @field numberOfRealtimeReceiveQueues The number of hardware queues available for AVB
            traffic reception. These are dedicated hardware queues with filtering that send
            packets into a provided callback rather than the regular network stack
        @field realtimeMulticastIsAllowed The transport layer allows for realtime traffic
            to be sent multicast. Ethernet networks typically respond as true, WiFi networks as false.
        @field packetMapper The IOMapper to be used for mapping the virtual memory used for packets to
            the physical address addresses used by the controller. May be NULL to indicate that it can use
            physical addresses from anywhere in the address space.
     */
    typedef struct
    {
        IOEthernetControllerAVBTimeSyncSupport timeSyncSupport;
        uint32_t numberOfRealtimeTransmitQueues;
        uint32_t numberOfRealtimeReceiveQueues;
        bool realtimeMulticastIsAllowed;
        IOMapper *packetMapper;
    } IOEthernetControllerAVBSupport;
    
    /*! @function getAVBSupport
        @abstract Indicates that AVB streaming is supported and what capabilities it has.
        @discussion
        @param avbSupport A pointer to an IOEthernetControllerAVBSupport struct to return the capabilities.
        @return True if this controller has at least 1 real time transmit queues or at least 1 realtime receive queues
     */
    bool getAVBSupport(IOEthernetControllerAVBSupport *avbSupport) const;
    
protected:
    /*! @function setRealtimeMulticastIsAllowed
        @abstract Sets up the realtime multicast allowed in the AVB support information.
        @discussion Used by subclasses to set the value returned in the realtimeMulticastIsAllowed
            field of the AVB support capabilities. This indicates if the transport allows the realtime
            AVB transmit queues to use multicast destination addresses. A transport such as WiFi where
            multicast drops to a low transfer rate would typically set this to false. Wired Ethernet
            would typically set this to true. The default value of a newly initialized object is true.
        @param realtimeMulticastAllowed bool indicating if the transport allows realtime streams to use multicast destination addresses.
     */
    void setRealtimeMulticastIsAllowed(bool realtimeMulticastAllowed);
    /*! @function setAVBPacketMapper
        @abstract Sets up the packet mapper in the AVB support information.
        @discussion Used by subclasses to set the value returned in the packetMapper field of the AVB
            support capabilities. This is used by the AVB stack to create the memory descriptors used
            for transmitting packets by the controller. The packet mapper is retained.
        @param packetMapper the IOMapper to be used.
     */
    void setAVBPacketMapper(IOMapper *packetMaper);
    
#pragma mark Interface State
    friend IOTimeSyncEthernetInterfaceAdapter;
public:
    /*! @function getControllerAVBState
        @abstract Get the current AVB state of the controller.
        @discussion The controller transitions through a number of AVB states depending on the
            services required by the AVB stack. The state transitions are triggered by a call to
            changeAVBControllerState() as the AVB stack transitions into and out of using TimeSync
            and/or streaming services
        @return The AVB state of the controller.
     */
    IOEthernetControllerAVBState getControllerAVBState(void) const;
    
    /*! @function changeAVBControllerState
        @abstract Change the AVB state of the AVB state of the controller.
        @discussion Called by the AVB stack to trigger changing of the controller AVB state machine
            based on what services the AVB stack requires.
        @param event The event to trigger the state machine change.
        @return IOReturn code indicating either success or reason for failure.
     */
    IOReturn changeAVBControllerState(IOEthernetControllerAVBStateEvent event);
    
    /*! @typedef avb_state_callback_t
        @abstract Callback function for notifying of AVB state changes
        @discussion Prototype for the callback function provided to the registerForAVBStateChangeNotifications()
            function for calling back to the requestor.
        @param context The context pointer that was provided in the call the registerForAVBStateChangeNotifications()
        @param newState The new state that the controller is now in.
     */
    typedef void (* avb_state_callback_t)(void *context, IOEthernetControllerAVBState oldState, IOEthernetControllerAVBState newState);
    
    //Allow the AVB stack or other interested drivers to register for notifications in the change of AVB state
    /*! @function registerForAVBStateChangeNotifications
        @abstract Function to register to receive callbacks whenever the AVB state changes.
        @discussion This function registers the callback function and context provided by the caller so that
            it can be called when the AVB state of the controller changes.
        @param callback A pointer to a callback function
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @return IOReturn code indicating success or a reason for failure.
     */
    IOReturn registerForAVBStateChangeNotifications(avb_state_callback_t callback, void *context);
    /*! @function deregisterForAVBStateChangeNotifications
        @abstract Function to deregister from receiving callbacks whenever the AVB state changes.
        @discussion This function deregisters the callback function and context provided by the caller so that
            it will stop being called when the AVB state of the controller changes. The provided values must
            match what was previously registered with registerForAVBStateChangeNotifications().
        @param callback A pointer to a callback function.
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @return IOReturn code indicating success or a reason for failure.
     */
    IOReturn deregisterForAVBStateChangeNotifications(avb_state_callback_t callback, void *context);
    
protected:
    /*! @function setAVBControllerState
        @abstract Set the controller to the new AVB state.
        @discussion This function is called as part of the changeAVBControllerState() processing and performs
            the change to the new state. This function is overriden by subclasses to perform any driver specific
            actions (such as enabling or disabling hardware features). Subclasses must call the base implementation
            and should be called last.
        @param newState The state to which the controller's AVB state machine will be set.
        @return IOReturn code indicating success or a reason for failure.
     */
    virtual IOReturn setAVBControllerState(IOEthernetControllerAVBState newState);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  2);
    
#pragma mark AVB Packets and Callbacks
public:
#define kMaxIOEthernetReltimeEntries    4
    
    struct IOEthernetAVBPacket;
    
    /*! @typedef avb_packet_callback_t
     @abstract Callback function for handling received realtime or TimeSync packets
     @discussion Prototype for the callback function provided to the setRealtimeReceiveQueuePacketHandler(),
     addTimeSyncReceivePacketHandler() and addTimeSyncTransmitPacketHandler() functions for calling back to the requestor.
     @param context The context pointer that was provided in the call the registerForAVBStateChangeNotifications()
     @param packet The packet being received or transmitted.
     */
    typedef void (* avb_packet_callback_t)(void *context, struct IOEthernetAVBPacket *packet);

    /*! @struct IOEthernetAVBPacket
        @abstract Structure containing an AVB or TimeSync packet.
        @discussion Structure containing the metadata for an AVB or TimeSync packet.
        @field structVersion The version of the packet structure. The only defined version is version 0 and this field shall be set to 0.
        @field numberOfEntries The number of entries in the virtualRanges and physicalRanges fields that contain
            valid addresses and lengths.
        @field virtualRanges The kernel virtual addresses of the buffer segments that make up the packet.
        @field physicalRanges The physical addresses of the mapped buffer segments that make up the packet.
        @field packetTimestamp The timestamp of the packet in mach_absolute_time() based time. For AVB realtime
            transmit packets this is the launch time of the packet, for AVB realtime receive packets this is
            optionally the ingress time of the packet. For TimeSync packets this is the egress time of transmitted
            packets or the ingress time of received packets.
        @field timestampValid Indicates if the packetTimestamp field contains a valid value.
        @field transmittedTimeSyncCallbackRef For transmited egress time stamped packets the callback reference
            returned by calling addTimeSyncTransmitPacketHandler(). This is required when calling transmitTimeSyncPacket().
        @field vlanTag The VLAN tag associated with the packet (includes the VLAN ID, Priority Code Point and Drop Eligable Indicator).
            This is typically used on receive paths to carry the VLAN tag that was stripped during reception.
        @field desc_buffer A field for the allocator to keep track of the buffer for memory management purposes. Use is allocator defined.
        @field desc_dma A field for the allocator to keep track of the DMA. Use is allocator defined.
        @field completion_context A pointer value for use in the completion callback
        @field completion_callback A callback function called by completeAVBPacket() to return the packet to the allocator when use is completed.
     */
    typedef struct IOEthernetAVBPacket
    {
        int structVersion;
        int numberOfEntries;
        IOVirtualRange virtualRanges[kMaxIOEthernetReltimeEntries];
        IOPhysicalRange physicalRanges[kMaxIOEthernetReltimeEntries];
        uint64_t packetTimestamp;
        bool timestampValid;
        uint32_t transmittedTimeSyncCallbackRef;
        
        uint16_t vlanTag;
        
        void *desc_buffer;
        void *desc_dma;
        void *completion_context;
        avb_packet_callback_t completion_callback;
        
        void *reservedAVBStack;
        void *reservedFamily;
    } IOEthernetAVBPacket;

    /*! @function completeAVBPacket
        @abstract Call the packet's completion callback to hand the packet back to the allocator of the packet for reuse or destruction.
        @discussion The completeAVBPacket function is called to provide the packet back to the allocator (or its delegate function).
            This is called by the owner of the IOEthernetAVBPacket when they have finished using it.
        @param packet The packet to be returned.
     */
    void completeAVBPacket(IOEthernetAVBPacket *packet);
    
    /*! @function allocateAVBPacket
        @abstract Allocate a packet from the AVB packet pool.
        @discussion Provide a packet from the AVB packet pool. The packet must eventually be returned by a call to completeAVBPacket().
            Packets allocated by this call will have one segment (numberOfEntries = 1) with a 2000 byte length. The caller must set the
            virtual and physical range lengths to the amount of data actually used for the packet.
        @param fromRealtimePool    If true pull the packet from the pre-allocated realtime pool, if false then allocate a new packet.
        @result The allocated packet. May return NULL if the pool is out of packets.
     */
    IOEthernetAVBPacket *allocateAVBPacket(bool fromRealtimePool);
    
    
private:
    static void allocatedAVBPacketCompletion(void *context, IOEthernetAVBPacket *packet);
    void realtimePoolAVBPacketCompletion(IOEthernetAVBPacket *packet);
    
    
#pragma mark Realtime Transmit
public:
    /*! @function getTransmitQueuePacketLatency
        @abstract Get the minimum amount of time required between when transmitRealtimePacket() is called and the launch timestamp.
        @discussion Get the packet latency, the minimum amount of time needed between when a packet is given to
            transmitRealtimePacket() and the launchTime when it is sent. This includes any prefetch delay (where the NIC fetches
            the data at most that amount of time before the launch time) and any descriptor setup time.
        @param queueIndex index of the realtime transmit queue.
        @return The number of mach_absolute_time ticks.
     */
    uint64_t getTransmitQueuePacketLatency(uint32_t queueIndex) const;

    /*! @function getTransmitQueuePrefetchDelay
        @abstract Get the maximum amount of time required between when NIC will DMA the packet contents and the launch timestamp.
        @discussion Get the prefetch delay, the maximum amount of time between when the NIC will DMA the packet contents and
            the launchTime when it is sent.
        @param queueIndex index of the realtime transmit queue.
        @return The number of mach_absolute_time ticks.
     */
    uint64_t getTransmitQueuePrefetchDelay(uint32_t queueIndex) const;
    
    /*! @function transmitRealtimePacket
        @abstract Transmit an AVB packet on a realtime transmit queue.
        @discussion Queues an AVB packet onto one of the controllers realtime transmit queues.
        @param queueIndex index of the realtime transmit queue.
        @param packets Array of the AVB packets to transmit.
        @param packetCount The number of AVB packets in the packets array.
        @param commonTimestamp All of the packets in the packets array share the same timestamp and the timestamp from the first packet
             should be used for scheduling all of the packets if needed by the hardware.
        @param successfulPacketCount The number of packets that were sucessfully added to the transmit queue.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn transmitRealtimePackets(uint32_t queueIndex, IOEthernetAVBPacket **packets, uint32_t packetCount, bool commonTimestamp, uint32_t *successfulPacketCount);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  3);
    
    //Clean up the realtime transmit queue (free up anything that has already been processed by the NIC)
    /*! @function cleanupTransmitQueue
        @abstract Cleanup the realtime transmit queue synchronously with AVB adding frames.
        @discussion This function performs necessary cleanup of the realtime transmit queue (cleaning through transmit
            descriptors) to free up space in the queue without needing to handle an interrupt. This is called from a
            realtime (priority 97) thread and care should be taken about use of locks and memory allocation/deallocation.
        @param queueIndex index of the realtime transmit queue.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn cleanupTransmitQueue(uint32_t queueIndex);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  4);
    
protected:
    /*! @function setNumberOfRealtimeTransmitQueues
        @abstract Sets up the realtime transmit queue count in the AVB support information.
        @discussion Used by subclasses to set the value returned in the numberOfRealtimeTransmitQueues field of the AVB
            support capabilities. It also initializes internal data structures to contain enough space for keeping track
            of realtime transmit queue information (such as the packet latency).
        @param numberOfTransmitQueues The number of transmit queues.
     */
    void setNumberOfRealtimeTransmitQueues(uint32_t numberOfTransmitQueues);
    /*! @function setTransmitQueuePacketLatency
        @abstract Set the value returned by getTransmitQueuePacketLatency() for a given queue.
        @discussion Stores the value of the minimum packet latency for a given queue. See getTransmitQueuePacketLatency for more details.
        @param queueIndex index of the realtime transmit queue.
        @param packetLatency The packet latency for the queue.
     */
    void setTransmitQueuePacketLatency(uint32_t queueIndex, uint64_t packetLatency);
    
    /*! @function setTransmitQueuePrefetchDelay
        @abstract Set the value returned by getTransmitQueuePrefetchDelay() for a given queue.
        @discussion Stores the value of the maximum prefetch delay for a given queue. See getTransmitQueuePrefetchDelay for more details.
        @param queueIndex index of the realtime transmit queue.
        @param PrefetchDelay The prefetch delay for the queue.
     */
    void setTransmitQueuePrefetchDelay(uint32_t queueIndex, uint64_t prefetchDelay);
    
#pragma mark Realtime Receive
public:
    /*! @enum Filter element types
     @abstract The type of the filter element described in an IOEthernetAVBIngressFilterElement struct.
     @const IOEthernetAVBIngressFilterTypeDestinationMAC Match a specific destination MAC address. Uses the destinationMAC field of the filter union.
     @const IOEthernetAVBIngressFilterTypeEtherTypeVLANTag Match a specific EtherType and VLAN Tag (Priority Code Point + VLAN ID). Uses the etherTypeVLANTag field of the filter union.
     @const IOEthernetAVBIngressFilterTypeUDPv4Port Match a specific UDPv4 source and/or destination port. Uses the udpPort field of the filter union.
     @const IOEthernetAVBIngressFilterTypeUDPv6Port Match a specific UDPv6 source and/or destination port. Uses the udpPort field of the filter union.
     @const IOEthernetAVBIngressFilterTypeIPv4Tuple Match a specific IPv4 tuple (source address, destination address, source port, destination port and protocol). Uses the ipv4Tuple field of the filter union.
     @const IOEthernetAVBIngressFilterTypeIPv6Tuple Match a specific IPv6 tuple (source address, destination address, source port, destination port and protocol). Uses the ipv6Tuple field of the filter union.
     @const IOEthernetAVBIngressFilterTypeMPLSLabel Match a specific MPLS Label. Uses the mplsLabel field of the filter union.
     @const IOEthernetAVBIngressFilterTypeByteMatch Match an aribitrary byte range up to 128 bytes long. Uses the byteMatch field of the filter union.
     @const IOEthernetAVBIngressFilterTypeCompound Provide an AND of more filter terms (takes each of the sub filters and ANDs together the results). Uses the compound field of the filter union.
     */
    typedef enum
    {
        IOEthernetAVBIngressFilterTypeDestinationMAC,
        IOEthernetAVBIngressFilterTypeEtherTypeVLANTag,
        IOEthernetAVBIngressFilterTypeUDPv4Port,
        IOEthernetAVBIngressFilterTypeUDPv6Port,
        IOEthernetAVBIngressFilterTypeIPv4Tuple,
        IOEthernetAVBIngressFilterTypeIPv6Tuple,
        IOEthernetAVBIngressFilterTypeMPLSLabel,
        IOEthernetAVBIngressFilterTypeByteMatch,
        IOEthernetAVBIngressFilterTypeCompound,
    } IOEthernetAVBIngressFilterType;
    
    /*! @enum Filter IP tuple protocol types
     @abstract The protocl that the IPv4 or IPv6 tuple match applies to.
     @const IOEthernetAVBIngressFilterProtocolTCP A TCP packet.
     @const IOEthernetAVBIngressFilterProtocolUDP A UDP packet.
     @const IOEthernetAVBIngressFilterProtocolSCTP An SCTP packet.
     @const IOEthernetAVBIngressFilterProtocolICMP An ICMP packet.
     */
    typedef enum
    {
        IOEthernetAVBIngressFilterProtocolTCP,
        IOEthernetAVBIngressFilterProtocolUDP,
        IOEthernetAVBIngressFilterProtocolSCTP,
        IOEthernetAVBIngressFilterProtocolICMP
    } IOEthernetAVBIngressFilterProtocol;
    
    /*! @struct IOEthernetAVBRealtimeIngressFilterElement
         @abstract One element in realtime receive queue ingress filter used to configure the hardware
         to send the packet to the specified receive queue.
         @discussion One element in realtime receive queue ingress filter used to configure the hardware
         to send the packet to the specified receive queue.
     
             For IOEthernetAVBRealtimeIngressFilterTypeEtherTypeVLANTag the element is applied as
                 (etherTypeVLANTag.etherType == (packet.etherType & etherTypeVLANTag.etherTypeMask)) && (etherTypeVLANTag.vlanTag == (packet.vlanTag & etherTypeVLANTag.vlanTagMask))
             For IOEthernetAVBRealtimeIngressFilterTypeUDPv4Port or IOEthernetAVBRealtimeIngressFilterTypeUDPv6Port the element is applied as
                 (udpPort.sourcePort == (packet.sourcePort & udpPort.sourcePortMask)) && (udpPort.destinationPort == (packet.destinationPort & udpPort.destinationPortMask))
         @field filterType The type of filter being added, defines which member of the union (filter) is used
         @field filter The union of all possible filter type fields.
     
         @field destinationMAC The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeDestinationMAC filter element.
         @field etherTypeVLANTag The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeEtherTypeVLANTag fiter element.
         @field udpPort The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeUDPv4Port or IOEthernetAVBIngressFilterTypeUDPv6Port filter element.
         @field ipv4Tuple The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeIPv4Tuple filter element.
         @field ipv6Tuple The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeIPv6Tuple filter element.
         @field mplsLabel The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeMPLSLabel filter element.
         @field byteMatch The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeByteMatch filter element.
         @field compound The struct containing matching parameters for an IOEthernetAVBIngressFilterTypeCompound filter element.
     
         @field macAddress The MAC address to match.
         @field macAddressMask The mask to apply to the destination MAC address of the packet to compare to the macAddress field.
     
         @field etherType The EtherType to match to send to the queue.
         @field etherTypeMask The mask to apply to the EtherType of the packet to compare to the etherType field.
         @field vlanTag The VLAN Tag (PCP and VID) to match to send to the queue.
         @field vlanTagMask The mask to apply to the VLAN tag of the packet to compare to the vlanTag field.
     
         @field sourcePort The source port to match.
         @field sourcePortMask The mask to apply to the source port of the packet to compare to the sourcePort field.
         @field destinationPort The destination port to match.
         @field destinationPortMask The mask to apply to the destination port of the packet to compare to the destinationPort field.
     
         @field sourceAddress The source address to match.
         @field sourceAddressMask The mask to apply to the source address of the packet to compare to the sourceAddress field.
         @field destinationAddress The destination address to match.
         @field destinationAddressMask The mask to apply to the destination address of the packet to compare to the destinationAddress field.
         @field protocol The protocol that the match applies to. See IOEthernetAVBIngressFilterProtocol.
     
         @field label The MPLS label to match
         @field labelMask The mask to apply to the MPLS label in the packet to compare to the label field.
     
         @field patternOffset The offset into the packet that the pattern match begins at.
         @field patternLength The number of bytes of pattern and pattern mask used in the match (maximum 128).
         @field pattern The pattern to match.
         @field patternMask The mask to apply to the bytes in the packet to compare to the pattern.
     
         @field elementCount The number of entries in the elements field.
         @field elements An array of IOEthernetAVBIngressFilterElement structs for sub filters to be ANDed together to make this filter element. These elements should not have sub elements.
     */
    typedef struct IOEthernetAVBIngressFilterElement
    {
        IOEthernetAVBIngressFilterType filterType;
        
        union
        {
            struct
            {
                uint8_t macAddress[kIOEthernetAddressSize];
                uint8_t macAddressMask[kIOEthernetAddressSize];
            } destinationMAC;
            
            struct
            {
                uint16_t etherType;
                uint16_t etherTypeMask;
                uint16_t vlanTag;
                uint16_t vlanTagMask;
            } etherTypeVLANTag;
            
            struct
            {
                uint16_t sourcePort;
                uint16_t sourcePortMask;
                uint16_t destinationPort;
                uint16_t destinationPortMask;
            } udpPort;
            
            struct
            {
                uint32_t sourceAddress;
                uint32_t sourceAddressMask;
                uint32_t destinationAddress;
                uint32_t destinationAddressMask;
                uint16_t sourcePort;
                uint16_t sourcePortMask;
                uint16_t destinationPort;
                uint16_t destinationPortMask;
                
                uint8_t protocol;
            } ipv4Tuple;
            
            struct
            {
                uint8_t sourceAddress[16];
                uint8_t sourceAddressMask[16];
                uint8_t destinationAddress[16];
                uint8_t destinationAddressMask[16];
                uint16_t sourcePort;
                uint16_t sourcePortMask;
                uint16_t destinationPort;
                uint16_t destinationPortMask;
                
                uint8_t protocol;
            } ipv6Tuple;

            struct
            {
                uint32_t label;
                uint32_t labelMask;
            } mplsLabel;
            
            struct
            {
                uint8_t patternOffset;
                uint8_t patternLength;
                uint8_t pattern[128];
                uint8_t patternMask[128];
            } byteMatch;
            
            struct
            {
                uint32_t elementCount;
                struct IOEthernetAVBIngressFilterElement *elements;
            } compound;
        } filter;
    } IOEthernetAVBIngressFilterElement;
    
    //Set the VLAN ID and PCP being used for a receive queue
    /*! @function setRealtimeReceiveQueueFilter
        @abstract Set the ingress filter being used for a receive queue.
        @discussion Sets the ingress filter hardware for directing the appropriate media streaming packets into the receive queue.
             Passing an empty array removes any added filters and either resets the queue to a default value or disables the queue.
        @param queueIndex index of the realtime receive queue.
        @param filterElements the array of IOEthernetAVBIngressFilterElement elements to apply as the ingress filter,
        @param filterElementCount the number of elements in the filterElements array.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn setRealtimeReceiveQueueFilter(uint32_t queueIndex, IOEthernetAVBIngressFilterElement *filterElements, uint32_t filterElementCount);
    OSMetaClassDeclareReservedUsed( IOEthernetInterface,  5);
    
    //Get the VLAN ID and PCP being used for a receive queue
    /*! @function getRealtimeReceiveQueueFilter
        @abstract Get the ingress filter being used for a receive queue.
        @discussion Gets the ingress filter hardware for directing the appropriate media streaming packets into the receive queue.
             The caller should call IOFree on any elements array within an IOEthernetAVBIngressFilterTypeCompound element.
        @param queueIndex index of the realtime receive queue.
        @param filterElements the array of IOEthernetAVBIngressFilterElement elements to apply as the ingress filter,
        @param filterElementCount the number of elements in the filterElements array. On entry this is the maximum size of the array.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn getRealtimeReceiveQueueFilter(uint32_t queueIndex, IOEthernetAVBIngressFilterElement *filterElements, uint32_t *filterElementCount);
    OSMetaClassDeclareReservedUsed( IOEthernetInterface,  6);
    
    /*! @function setRealtimeReceiveQueuePacketHandler
        @abstract Set the packet handler callback function for a realtime receive queue.
        @discussion Sets the callback function and context to be used to process all of the packets for a realtime receive queue.
            Ownership of the packets is handed from the driver to the callback function. The callback function must call completeAVBPacket()
            before returning.
        @param queueIndex index of the realtime receive queue.
        @param callback The callback function pointer.
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn setRealtimeReceiveQueuePacketHandler(uint32_t queueIndex, avb_packet_callback_t callback, void *context);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  7);
    
    /*! @function setRealtimeReceiveDestinationMACList
        @abstract Set the list of destination MAC addreses used for a realtime receive queue.
        @discussion Set the list of destination MAC addresses that are being received on a realtime receive queue. These multicast
            addresses are *not* included in the list supplied to the setMulticastList call.
        @param queueIndex index of the realtime receive queue.
        @param addresses An array of ethernet destination MAC addresses. This shall be ignored if addressCount is 0.
        @param addressCount The number of elements in the addresses array.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn setRealtimeReceiveDestinationMACList(uint32_t queueIndex, IOEthernetAddress *addresses, int addressCount);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  8);
    
protected:
    /*! @function setNumberOfRealtimeReceiveQueues
        @abstract Sets up the realtime receive queue count in the AVB support information.
        @discussion Used by subclasses to set the value returned in the numberOfRealtimeReceiveQueues field of the AVB
            support capabilities. It also initializes internal data structures to contain enough space for keeping track
            of realtime receive queue information (such as the callbacks).
        @param numberOfReceiveQueues The number of receive queues.
     */
    void setNumberOfRealtimeReceiveQueues(uint32_t numberOfReceiveQueues);
    
#pragma mark Time Sync
public:
    /*! @function addTimeSyncReceivePacketHandler
        @abstract Add a callback function to the list of Time Sync receive callbacks.
        @discussion Add a callback function to the set of callbacks that are called for every received time sync packet.
            Ownership of the packet is not handed to the callback function. The callback function must not call completeAVBPacket().
        @param callback The function to be called upon receiving a Time Sync packet in the dedicated time sync receive queue.
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @return IOReturn indicating success or reason for failure.
     */
    IOReturn addTimeSyncReceivePacketHandler(avb_packet_callback_t callback, void *context);
    /*! @function removeTimeSyncReceivePacketHandler
        @abstract Remove a previously added callback.
        @discussion Remove a callback function that was previously added with addTimeSyncReceivePacketHandler().
        @param callback The function previously added.
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @return IOReturn indicating success or reason for failure.
     */
    IOReturn removeTimeSyncReceivePacketHandler(avb_packet_callback_t callback, void *context);
    
    //Set the callback for transmitted time sync packets (those that require egress timestamping)
    /*! @function addTimeSyncTransmitPacketHandler
        @abstract Add a callback function to be called after transmitting an egress timestamped Time Sync packet.
        @discussion Add a callback function to the list and assigns a reference to it for tracking the callback to be used
            for returning the egress timestamp to the caller. Ownership of the packet is not handed to the callback function.
            The callback function must not call completeAVBPacket().
        @param callback The function to be called upon transmitting a Time Sync packet and obtaining it's egress timestamp.
        @param context A caller specified pointer sized value that is passed back in the callback function.
        @param callbackRef A pointer to a uint32_t that is allocated to the callback for use in the packets passed
            to the transmitTimeSyncPacket so that the callback will be called.
        @return IOReturn indicating success or reason for failure.
     */
    IOReturn addTimeSyncTransmitPacketHandler(avb_packet_callback_t callback, void *context, uint32_t *callbackRef);
    /*! @function removeTimeSyncTransmitPacketHandler
        @abstract Remove a callback function previously added with addTimeSyncTransmitPacketHandler()
        @discussion Remove a transmit packet handler previously added with addTimeSyncTransmitPacketHandler().
        @param callbackRef The callback reference returned by the call to addTimeSyncTransmitPacketHandler().
        @return IOReturn indicating success or reason for failure.
     */
    IOReturn removeTimeSyncTransmitPacketHandler(uint32_t callbackRef);
    
    /*! @function transmitTimeSyncPacket
        @abstract Transmit a time sync packet and capture it's egress timestamp.
        @discussion Transmit a time sync packet which requires egress timestamping, after the egress timestamp is available
            the transmit packet handler is called, passing this packet. If expiryTime (in mach_absolute_time) is reached
            before the packet is transmitted it is aborted the packet callback called with the packet containing no valid timestamp.
        @param packet The packet to be transmitted.
        @param expiryTime The time at which the packet no longer needs to be transmitted if it hasn't already been transmitted.
        @return IOReturn indicating success or reason for failure.
     */
    virtual IOReturn transmitTimeSyncPacket(IOEthernetAVBPacket * packet, uint64_t expiryTime);
    OSMetaClassDeclareReservedUsed( IOEthernetController,  9);
    
    
protected:
    /*! @function setGPTPPresent
        @abstract Set the gPTP present flag on the controller and trigger the AVB stack loading.
        @discussion Sets the gPTPPresent property on the controller and interface. If setting gPTPPresent to true it calls
            registerService() to trigger matching and loading of the AVB stack on demand, otherwise it calls messageClients
            to trigger the stack to unload.
        @param gPTPPresent
        @return IOReturn indicating success or reason for failure.
     */
    IOReturn setGPTPPresent(bool gPTPPresent);
    
protected:
    /*! @function receivedTimeSyncPacket
        @abstract Send the received time sync packet to the callback functions.
        @discussion This function is called by subclasses when they have received a Time Sync packet to send it to all of the
            registered callback functions.
        @param packet The received time sync packet.
     */
    void receivedTimeSyncPacket(IOEthernetAVBPacket *packet);
    /*! @function transmittedTimeSyncPacket
        @abstract Send the transmitted time sync packet to the transmit callback.
        @discussion This function is called by subclasses when they have transmitted an egress timestamped packet and have the
            egress timestamp or when they have expired the packet.
        @param packet The transmitted time sync packet
        @param expired A bool indicating if the call is due to the packet being expired.
     */
    void transmittedTimeSyncPacket(IOEthernetAVBPacket *packet, bool expired);

    /*! @function setTimeSyncPacketSupport
        @abstract Sets up the time sync support in the AVB support information
        @discussion Used by subclasses to set the value returned in the timeSyncSupport field of the AVB support caoabilities.
        @param timeSyncPacketSupport The support that the controller has for timestamping.
     */
    void setTimeSyncPacketSupport(IOEthernetControllerAVBTimeSyncSupport timeSyncPacketSupport);
    
private:
    static void timeSyncCallbackThreadEntry(void *param, wait_result_t waitResult);
    void timeSyncCallbackThread(void);
    
    
    
    
    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IOEthernetController, 10);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 11);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 12);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 13);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 14);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 15);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 16);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 17);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 18);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 19);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 20);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 21);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 22);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 23);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 24);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 25);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 26);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 27);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 28);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 29);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 30);
    OSMetaClassDeclareReservedUnused( IOEthernetController, 31);
};

/*
 * FIXME: remove this.
 */
enum {
    kIOEnetPromiscuousModeOff   = false,
    kIOEnetPromiscuousModeOn    = true,
    kIOEnetPromiscuousModeAll   = true,
    kIOEnetMulticastModeOff     = false,
    kIOEnetMulticastModeFilter  = true
};
typedef bool IOEnetPromiscuousMode;
typedef bool IOEnetMulticastMode;

#endif /* __cplusplus */
#endif /* KERNEL */
#endif /* !_IOETHERNETCONTROLLER_H */
