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

#ifndef _IONETWORKINTERFACE_H
#define _IONETWORKINTERFACE_H

/*! @defined kIONetworkInterfaceClass
    @abstract The name of the IONetworkInterface class. 
*/

#define kIONetworkInterfaceClass  "IONetworkInterface"

/*! @defined kIONetworkData
    @abstract A property of IONetworkInterface objects. 
    @discussion The kIONetworkData property has an OSDictionary value and is a
        container for the set of IONetworkData objects managed by the interface.
        Each entry in the dictionary is a key/value pair consisting of
        the network data name, and an OSDictionary describing the
        contents of the network data. 
*/

#define kIONetworkData            "IONetworkData"

/*! @defined kIOInterfaceType
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceType property has an OSNumber value that
        specifies the type of network interface that this interface represents.
        The type constants are defined in bsd/net/if_types.h. 
*/

#define kIOInterfaceType          "IOInterfaceType"

/*! @defined kIOMaxTransferUnit
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOMaxTransferUnit property has an OSNumber value that
        specifies the maximum transfer unit for the interface in bytes.
*/

#define kIOMaxTransferUnit        "IOMaxTransferUnit"

/*! @defined kIOMediaAddressLength
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOMediaAddressLength property has an OSNumber value that
        specifies the size of the media address in bytes. 
*/

#define kIOMediaAddressLength     "IOMediaAddressLength"

/*! @defined kIOMediaHeaderLength
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOMediaHeaderLength property has an OSNumber value that
        specifies the size of the media header in bytes. 
*/

#define kIOMediaHeaderLength      "IOMediaHeaderLength"

/*! @defined kIOInterfaceFlags
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceFlags property has an OSNumber value that
        specifies the current value of the interface flags. The flag constants
        are defined in bsd/net/if.h. 
*/

#define kIOInterfaceFlags         "IOInterfaceFlags"

/*! @defined kIOInterfaceExtraFlags
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceExtraFlags property has an OSNumber value that
        specifies the current value of the interface eflags. The eflag constants
        are defined in bsd/net/if.h. 
*/

#define kIOInterfaceExtraFlags    "IOInterfaceExtraFlags"

/*! @defined kIOInterfaceUnit
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceUnit property has an OSNumber value that
        describes the unit number assigned to the interface object. 
*/

#define kIOInterfaceUnit          "IOInterfaceUnit"

/*! @defined kIOInterfaceState
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceState property has an OSNumber value that
        describes the current state of the interface object. This property is
        not exported to BSD via the ifnet structure. 
*/

#define kIOInterfaceState         "IOInterfaceState"

/*! @defined kIOInterfaceNamePrefix
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceNamePrefix property has an OSString value that
        describes the string prefix for the BSD name assigned to the interface. 
*/

#define kIOInterfaceNamePrefix    "IOInterfaceNamePrefix"

/*! @defined kIOPrimaryInterface
    @abstract A property of IONetworkInterface objects.
    @discussion The kIOInterfaceNamePrefix property has an OSBoolean value that
        describes whether the interface is the primary or the built-in network
        interface. 
*/

#define kIOPrimaryInterface       "IOPrimaryInterface"

/*! @defined kIOBuiltin
    @abstract kIOBuiltin is a property of IONetworkInterface
        objects. It has an OSBoolean value.
    @discussion The kIOBuiltin property describes whether the
        interface is built-in. 
*/

#define kIOBuiltin                "IOBuiltin"

/*! @defined kIOLocation
    @abstract kIOLocation is a property of IONetworkInterface
        objects. It has an OSString value.
    @discussion The kIOLocation property describes the physical 
        location of built-in interfaces. 
*/

#define kIOLocation               "IOLocation"

/*! @defined kIONetworkNoBSDAttachKey
    @abstract kIONetworkNoBSDAttachKey is a property of IONetworkInterface
        objects. It has an OSBoolean value.
    @discussion Adding a property with this key and the value kOSBooleanTrue
        before the interface is published will hold off the BSD attach.
        When the interface is ready to attach to BSD, remove the property
        and then re-publish the interface by calling registerService().
*/

#define kIONetworkNoBSDAttachKey  "IONetworkNoBSDAttach"

/*! @enum InterfaceObjectStates
    @discussion Constants used to encode the state of the interface object.
   @constant kIONetworkInterfaceRegisteredState The interface object has
        registered with the data link layer.
    @constant kIONetworkInterfaceOpenedState One or more clients have an
        open on the interface object.
    @constant kIONetworkInterfaceDisabledState The interface is temporarily
        unable to service its clients. This will occur when the network
        controller that is servicing the interface has entered a low power
        state that renders it unusable. 
*/

enum {
    kIONetworkInterfaceRegisteredState  = 0x1,
    kIONetworkInterfaceOpenedState      = 0x2,
    kIONetworkInterfaceDisabledState    = 0x4
};

#ifdef KERNEL
#ifdef __cplusplus

#include <IOKit/IOService.h>
#include <IOKit/network/IONetworkData.h>
#include <IOKit/network/IONetworkStats.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/kpi_interface.h>

class  IONetworkController;
class  IONetworkStack;
class  IOCommandGate;
struct IOMbufQueue;

/*! @typedef IOOutputAction
    @discussion Prototype for an output packet handler that will process
    all outbound packets sent to the interface from the data link layer.
    An output handler is registered with the interface by calling
    registerOutputHandler().
    @param mbuf_t A packet mbuf.
    @param param A parameter for the output request. */

typedef UInt32 (OSObject::*IOOutputAction)(mbuf_t, void * param);

/*! @typedef BPF_FUNC
    @discussion Prototype for the BPF tap handler. This will disappear
    when the correct DLIL header file is included. */

typedef int (*BPF_FUNC)(struct ifnet *, struct mbuf *);

// Network event types recognized by inputEvent().
//
enum {
    /* DLIL defined event, argument must be a pointer to a
       kern_event_msg structure. */
    kIONetworkEventTypeDLIL                 = 0xff000001,

    /* Link up event, no argument */
    kIONetworkEventTypeLinkUp               = 0xff000002,

    /* Link down event, no argument */
    kIONetworkEventTypeLinkDown             = 0xff000003,

    /* Wake on LAN support changed, no argument */
    kIONetworkEventWakeOnLANSupportChanged  = 0xff000004,
    
    /* Link speed changed */
    kIONetworkEventTypeLinkSpeedChange      = 0xff000005
};

#ifdef __PRIVATE_SPI__
enum {
    kIONetworkWorkLoopSynchronous   = 0x00000001
};

/*! @enum IOMbufServiceClass
    @discussion Service class of a mbuf packet.
    @constant kIOMbufServiceClassBKSYS Background System-Initiated.
    @constant kIOMbufServiceClassBK  Background.
    @constant kIOMbufServiceClassBE  Best Effort.
    @constant kIOMbufServiceClassRD  Responsive Data.
    @constant kIOMbufServiceClassOAM Operations, Administration, and Management.
    @constant kIOMbufServiceClassAV  Multimedia Audio/Video Streaming.
    @constant kIOMbufServiceClassRV  Responsive Multimedia Audio/Video.
    @constant kIOMbufServiceClassVI  Interactive Video.
    @constant kIOMbufServiceClassVO  Interactive Voice.
    @constant kIOMbufServiceClassCTL Network Control.
*/
enum IOMbufServiceClass {
    kIOMbufServiceClassBKSYS    = 100,
    kIOMbufServiceClassBK       = 200,
    kIOMbufServiceClassBE       = 0,
    kIOMbufServiceClassRD       = 300,
    kIOMbufServiceClassOAM      = 400,
    kIOMbufServiceClassAV       = 500,
    kIOMbufServiceClassRV       = 600,
    kIOMbufServiceClassVI       = 700,
    kIOMbufServiceClassVO       = 800,
    kIOMbufServiceClassCTL      = 900
};

/*! @enum IONetworkTransmitStatus
    @discussion Constants for packet transmit status.
    @constant kIONetworkTransmitStatusSuccess Packet sent across link.
    @constant kIONetworkTransmitStatusFailed  Failed to send packet across link.
    @constant kIONetworkTransmitStatusAborted Send aborted, peer was asleep.
    @constant kIONetworkTransmitStatusQueueFull Driver send queue was full.
*/
enum {
    kIONetworkTransmitStatusSuccess     = 0,
    kIONetworkTransmitStatusFailed      = 1,
    kIONetworkTransmitStatusAborted     = 2,
    kIONetworkTransmitStatusQueueFull   = 3
};

typedef uint32_t IONetworkTransmitStatus;

/*! @typedef IONetworkPacketPollingParameters
    @discussion Mirrors the definition of <code>ifnet_poll_params()</code>.
    @field maxPacketCount The maximum number of packets to be dequeued each
    time the driver's <code>pollInputPackets</code> is invoked. A zero value
    indicates the use of default maximum defined by the system.
    @field lowThresholdPackets Low watermark packets threshold.
    @field highThresholdPackets High watermark packets threshold.
    @field lowThresholdBytes Low watermark bytes threshold.
    @field highThresholdBytes High watermark bytes threshold.
    @field pollIntervalTime The interval time between each invocation of
    the driver's <code>pollInputPackets</code> in nanoseconds.
*/
struct IONetworkPacketPollingParameters {
    uint32_t    maxPacketCount;
    uint32_t    lowThresholdPackets;
    uint32_t    highThresholdPackets;
    uint32_t    lowThresholdBytes;
    uint32_t    highThresholdBytes;
    uint64_t    pollIntervalTime;
    uint64_t    reserved[4];
};
#endif /* __PRIVATE_SPI__ */

/*! @class IONetworkInterface
    @abstract Abstract class that manages the connection between an
    IONetworkController and the data link interface layer.
    @discussion An IONetworkInterface object manages the connection between
    an IONetworkController and the data link interface layer (DLIL).
    All interactions between the controller and DLIL must go through an
    interface object. Any data structures that are required by DLIL for a
    particular interface type shall be allocated and mantained by the
    interface object. IONetworkInterface is an abstract class that must be
    extended by a concrete subclass to specialize for a particular network
    type.

    Although most drivers will allocate a single interface object,
    it is possible for multiple interfaces to be attached to a single
    controller. This controller driver will be responsible for arbitrating
    access among its multiple interface clients.
    
    IONetworkInterface also maintains a dictionary of IONetworkData
    objects containing statistics structures. Controller drivers can
    ask for a particular data object by name and update the
    statistics counters within directly. This dictionary is added to
    the interface's property table and is visible outside of the kernel. 
*/

class IONetworkInterface : public IOService
{
    OSDeclareAbstractStructors( IONetworkInterface )

    friend class IONetworkStack;

#ifdef __PRIVATE_SPI__
public:
/*! @typedef OutputPreEnqueueHandler
    @param target Reference supplied when the handler was installed.
    @param refCon Reference supplied when the handler was installed.
    @param packet The output packet; may be the head of a chain of packets.
    Call <code>enqueueOutputPacket()</code> for each packet in the chain to
    enqueue the packet before returning. The handler executes on the thread
    context of the sending client.
*/
    typedef errno_t (*OutputPreEnqueueHandler)(
        void * target, void * refCon, mbuf_t packet );

    static IOReturn errnoToIOReturn( errno_t error );
#endif /* __PRIVATE_SPI__ */

private:
    IONetworkController *   _driver;
    ifnet_t                 _backingIfnet;
    IOLock *                _privateLock;
    OSSet *                 _clientSet;
    OSNumber *              _stateBits;
    bpf_packet_func         _inputFilterFunc;
    bpf_packet_func         _outputFilterFunc;
    OSObject *              _outTarget;
    IOOutputAction          _outAction;
    UInt32                  _clientVar[4];
    OSDictionary *          _dataDict;
    IOMbufQueue *           _inputPushQueue;
    void *                  _unused1;
    UInt32                  _unused2;

    struct ExpansionData {
        int                         unit;
        int                         type;
        int                         mtu;
        int                         flags;
        int                         eflags;
        int                         addrlen;
        int                         hdrlen;
        int32_t                     loggingLevel;
        uint32_t                    outputQueueModel;
        IONetworkStats              driverStats;
        IONetworkStats              lastDriverStats;
        ifnet_stat_increment_param  inputDeltas;
        IORecursiveLock *           publicLock;
        char *                      remote_NMI_pattern;
        unsigned int                remote_NMI_len;
        IONetworkController *       controller;
        uint32_t                    configFlags;
        uint32_t                    txRingSize;
        uint32_t                    txPullOptions;
        uint32_t                    txQueueSize;
        uint32_t                    txSchedulingModel;
        uint32_t                    txThreadState;
        volatile UInt32             txThreadFlags;
        uint32_t                    txThreadSignal;
        uint32_t                    txThreadSignalLast;
        thread_t                    txStartThread;
        void *                      txStartAction;
        IOWorkLoop *                txWorkLoop;
        uint32_t                    rxRingSize;
        uint32_t                    rxPollOptions;
        uint32_t                    rxPollModel;
        void *                      rxPollAction;
        void *                      rxCtlAction;        
        uint64_t                    rxPollEmpty;
        uint64_t                    rxPollTotal;
#ifdef __PRIVATE_SPI__
        OutputPreEnqueueHandler     peqHandler;
        void *                      peqTarget;
        void *                      peqRefcon;
        uint32_t                    subType;
#endif
    };

    ExpansionData *         _reserved;

    bool            _syncNetworkDataDict();
    SInt32          syncSIOCSIFMEDIA(IONetworkController * ctr, struct ifreq * ifr);
    SInt32          syncSIOCGIFMEDIA(IONetworkController * ctr, struct ifreq * ifr,
                                unsigned long cmd);
    SInt32          syncSIOCSIFMTU(IONetworkController * ctr, struct ifreq * ifr);
    void            drainOutputQueue(ifnet_t ifp, IONetworkController * driver);
    IOReturn        haltOutputThread(uint32_t stateBit);
#ifdef __PRIVATE_SPI__
    void            actionInputCtl(IONetworkController * driver,
                                ifnet_ctl_cmd_t cmd, uint32_t arglen, void * arg );
#endif
    void            pushInputQueue( IOMbufQueue * queue );
    void            pushInputPacket( mbuf_t packet, uint32_t length );
    int             if_start_precheck( ifnet_t ifp );
    static int      performGatedCommand(void *, void *, void *, void *, void *);
    static void     powerChangeHandler(void *, void *, void *);
    static errno_t  if_ioctl(ifnet_t ifp, unsigned long cmd, void * data);
    static int      if_output(ifnet_t ifp, mbuf_t);
    static errno_t  if_set_bpf_tap(ifnet_t ifp, bpf_tap_mode, bpf_packet_func);
	static void     if_detach(ifnet_t ifp);
    static void     if_start(ifnet_t ifp);
    static void     if_start_gated(ifnet_t ifp);
    static void     if_input_poll(ifnet_t ifp, uint32_t flags,
                                uint32_t max_count,
                                mbuf_t * first_packet, mbuf_t * last_packet,
                                uint32_t *  cnt, uint32_t * len);
    static void     if_input_poll_gated(ifnet_t ifp, uint32_t flags,
                                uint32_t max_count,
                                mbuf_t * first_packet, mbuf_t * last_packet,
                                uint32_t *  cnt, uint32_t * len);
#ifdef __PRIVATE_SPI__
    static errno_t  if_input_ctl(ifnet_t ifp, ifnet_ctl_cmd_t cmd,
                                 uint32_t arglen, void * arg);
    static errno_t  if_output_pre_enqueue(ifnet_t ifp, mbuf_t packet);
    static errno_t  if_output_ctl(ifnet_t ifp, ifnet_ctl_cmd_t cmd,
                                  u_int32_t arglen, void *arg);
#endif
    void            notifyDriver( uint32_t type, void * data );

public:

/*! @function isPrimaryInterface
    @abstract Queries whether the interface is the primary network interface
    on the system.
    @discussion The definition of a primary interface and its discovery is
    platform specific.
    @result Returns true if the interface is the primary interface,
    false otherwise.
*/
    virtual bool     isPrimaryInterface( void ) const;

/*! @function init
    @abstract Initializes the <code>IONetworkInterface</code> object.
    @discussion Resources are allocated, but an <code>ifnet_t</code> will not
    be allocated until the interface is assigned a BSD name and attached to the
    network stack.
    @param controller A network controller object that will service the
    the interface.
    @result Returns true on success, false otherwise.
*/
    virtual bool     init( IONetworkController * controller );

/*! @function isRegistered
    @abstract Queries if the interface has attached to the BSD network stack.
    @discussion Once attached a <code>kIOBSDNameKey</code> property is added
    to the interface object with the assigned BSD name.
    @result Returns true if interface is registered and attached to the network
    stack, false otherwise.
*/
    virtual bool     isRegistered( void ) const;

/*! @function getInterfaceState
    @abstract Reports the current state of the interface object.
    @result Returns the current interface state flags.
*/
    virtual UInt32   getInterfaceState( void ) const;

/*! @function getController
    @abstract Gets the <code>IONetworkController</code> object that created
    this interface.
    @discussion The controller object passed to init() will be retained until
    the interface closes the controller. Subclasses can safely call this method
    before the controller is closed.
    @result Returns the parent <code>IONetworkController</code> object.
*/
    virtual IONetworkController * getController( void ) const;

/*! @function inputPacket
    @abstract For drivers to submit a received packet to the network stack.
    @discussion The packet provided to this method may be added to an input
    queue managed by the interface object, which the driver can use to postpone
    the packet handoff to the network stack, until all received packets have been
    added to the input queue. A subsequent call to <code>flushInputQueue()</code>,
    will transfer the entire contents of the input queue to the network stack.
    This input queue is not protected by a lock. Drivers that leverage this
    input queue must either access the queue from a single thread, or enforce
    serialized access.
    @param mbuf_t The mbuf containing the received packet.
    @param length Specify the size of the received packet in the mbuf.
    The mbuf length fields are updated with this value. If zero, then the mbuf
    length fields are not updated.
    @param options Pass <code>kInputOptionQueuePacket</code> to enqueue the
    input packet. Pass zero to bypass the input queue, and immediately submit
    the packet to the network stack.
    @param param A parameter provided by the driver. Not used.
    @result Returns the number of packets that were submitted to the network
    stack, or zero if the packet was enqueued.
*/
    virtual UInt32   inputPacket(
                        mbuf_t          packet,
                        UInt32          length  = 0,
                        IOOptionBits    options = 0,
                        void *          param   = 0 );

/*! @enum InputOptionQueuePacket
    @discussion Options for <code>inputPacket()</code>.
    @constant kInputOptionQueuePacket Enqueue the input packet provided to the
    input packet queue. Calls to <code>inputPacket()</code> must be serialized.
*/
    enum {
        kInputOptionQueuePacket = 0x1
    };

/*! @function flushInputQueue
    @abstract Submit all packets held in the input queue to the network stack.
    @discussion Allow drivers to remove all packets from the input queue and
    submit them to the network stack. This method should be used in concert
    with the <code>inputPacket()</code> method, to flush the input queue after
    queueing a number of received packets.
    @result Returns the number of packets that were submitted to the network
    stack. Returns zero if the queue was empty.
*/
    virtual UInt32   flushInputQueue( void );

/*! @function clearInputQueue
    @abstract Discards all packets in the input queue.
    @discussion This method removes all packets from the input queue and
    releases them back to the free mbuf pool. It is unusual for a driver to
    call this method.
    @result Returns the number of packets freed.
*/
    virtual UInt32   clearInputQueue( void );

/*! @function inputEvent
    @abstract Sends an event to the network stack.
    @discussion This method can be used by the driver to send an event to the
    network stack.
    @param type A constant describing the event type.
    @param data An optional data associated with the event.
    @result Returns true if the event was delivered, false if the event type
    specified is invalid, or if the event delivery failed.
*/
    virtual bool     inputEvent( UInt32 type, void * data );

/*! @function registerOutputHandler
    @abstract Registers a target/action to handle outbound packets.
    @discussion The interface object will forward all output packets sent from
    the network stack to the target and action registered using this method.
    The registration must occur before the interface is registered and opened
    by <code>IONetworkStack</code>, otherwise the default handler will be used.
    The default target and action is set by <code>init()</code> as the
    controller, and the handler returned by the controller's
    <code>getOutputHandler()</code> method.
    @param target Object that implements the output handler.
    @param action The function that will handle output packets.
    @result Returns true if the target/action provided was accepted,
    false otherwise.
*/
    virtual bool     registerOutputHandler(
                            OSObject *      target,
                            IOOutputAction  action );

/*! @function getNamePrefix
    @abstract Returns the BSD name prefix as a C-string.
    @discussion The BSD name for each interface object is generated by
    concatenating the string returned by this method, along with an unit number
    assigned by <code>IONetworkStack</code>. A concrete interface subclass must
    implement this method and return a distinct name prefix for its instances.
    @result Returns a pointer to a constant C-string.
*/
    virtual const char * getNamePrefix() const = 0;

/*! @function getInterfaceType
    @abstract Gets the interface type.
    @discussion This method returns the interface type previously set by
    <code>setInterfaceType</code>.
    @result Returns a constant defined in <code>bsd/net/if_types.h</code>
    that describes the interface type.
*/
    virtual UInt8    getInterfaceType( void ) const;

/*! @function getMaxTransferUnit
    @abstract Gets the maximum transfer unit for this interface.
    @discussion This method calls <code>ifnet_mtu</code> and returns the
    maximum transfer unit.
    @result Returns the interface MTU size in bytes.
*/
    virtual UInt32   getMaxTransferUnit( void ) const;

/*! @function getFlags
    @abstract Gets the current interface flags.
    @discussion This method calls <code>ifnet_flags</code> and returns the
    current interface flags.
    @result Returns the interface flags.
*/
    virtual UInt16   getFlags( void ) const;

/*! @function getExtraFlags
    @abstract Gets the current interface eflags.
    @discussion This method calls <code>ifnet_eflags</code> and returns the
    current interface eflags.
    @result Returns the value of the interface eflags.
*/
    virtual UInt32   getExtraFlags( void ) const;

/*! @function getMediaAddressLength
    @abstract Gets the size of the media (MAC-layer) address.
    @discussion This method calls <code>ifnet_addrlen</code> and returns the
    media address length.
    @result Returns the size of the media address in bytes.
*/
    virtual UInt8    getMediaAddressLength( void ) const;

/*! @function getMediaHeaderLength
    @abstract Gets the size of the media header.
    @discussion This method calls <code>ifnet_hdrlen</code> and returns the
    media header length.
    @result Returns the size of the media header in bytes.
*/
    virtual UInt8    getMediaHeaderLength( void ) const;

/*! @function getUnitNumber
    @abstract Gets the unit number assigned to this interface object.
    @discussion This method calls <code>ifnet_unit</code> and returns the
    unit number assigned by <code>IONetworkStack</code>.
    @result Returns the assigned interface unit number.
*/
    virtual UInt16   getUnitNumber( void ) const;

/*! @function addNetworkData
    @abstract Adds an <code>IONetworkData</code> object to the interface.
    @discussion The <code>IONetworkData</code> object is added to a
    collection using the key from <code>IONetworkData::getKey()<code>.
    The object provided is retained.
    @param aData The <code>IONetworkData</code> object.
    @result Returns true if the object was added, false otherwise.
*/
    virtual bool     addNetworkData( IONetworkData * aData );

/*! @function removeNetworkData
    @abstract Removes an <code>IONetworkData</code> object from the interface.
    @discussion This method removes an <code>IONetworkData</code> object from
    the collection managed by the interface. The object removed is released.
    @param aKey An OSSymbol identifying the object to be removed.
    @result Returns true if the object was found and removed, false otherwise.
*/
    virtual bool     removeNetworkData( const OSSymbol * aKey );

/*! @function removeNetworkData
    @abstract Removes an <code>IONetworkData</code> object from the interface.
    @discussion This method removes an <code>IONetworkData</code> object from
    the collection managed by the interface. The object removed is released.
    @param aKey A C-string identifying the object to be removed.
    @result Returns true if the object was found and removed, false otherwise.
*/
    virtual bool     removeNetworkData( const char * aKey );

/*! @function getNetworkData
    @abstract Gets an <code>IONetworkData</code> object from the interface.
    @discussion Returns a reference to an <code>IONetworkData</code> object
    that was previously added to the interface, and is associated with the
    provided key.
    @param aKey A C-string identifying the object.
    @result Returns a reference to the matching <code>IONetworkData</code>
    object, or NULL if no match was found.
*/
    virtual IONetworkData * getNetworkData( const char * aKey ) const;

/*! @function getNetworkData
    @abstract Gets an <code>IONetworkData</code> object from the interface.
    @discussion Returns a reference to an <code>IONetworkData</code> object
    that was previously added to the interface, and is associated with the
    provided key.
    @param aKey An OSSymbol identifying the object.
    @result Returns a reference to the matching <code>IONetworkData</code>
    object, or NULL if no match was found.
*/
    virtual IONetworkData * getNetworkData(const OSSymbol * aKey) const;

    /* Compatibility methods */
    IONetworkData * getParameter(const char * aKey) const;
	bool setExtendedFlags(UInt32 flags, UInt32 clear = 0);

    /* Override IOService::message() */
    virtual IOReturn message( UInt32 type, IOService * provider, void * argument );

/*! @function debuggerRegistered
    @abstract Tells the <code>IONetworkData</code> that this interface will be
    used by the debugger.
*/
    void debuggerRegistered( void );

protected:
/*! @function setInterfaceType
    @abstract Sets the interface type.
    @discussion Sets the interface type before the interface is attached to
    the network stack. See <code>bsd/net/if_types.h</code> for defined types.
    The <code>kIOInterfaceType</code> is also updated using the provided type.
    @param type A constant defined in <code>bsd/net/if_types.h</code> that
    describes the interface type.
    @result Returns true to indicate success if the interface has not yet
    attached to the network stack, otherwise returns false.
*/
    virtual bool     setInterfaceType( UInt8 type );

/*! @function setMaxTransferUnit
    @abstract Sets the maximum transfer unit for this interface.
    @discussion Calls <code>ifnet_set_mtu</code> if the interface is attached
    to the network stack, and updates the <code>kIOMaxTransferUnit</code>
    property using the provided value.
    @param mtu The interface MTU size in bytes.
    @result Always returns true.
*/
    virtual bool     setMaxTransferUnit( UInt32 mtu );

/*! @function setFlags
    @abstract Performs a read-modify-write operation on the current
    interface flags value.
    @discussion Calls <code>ifnet_set_flags</code> if the interface is attached
    to the network stack, and updates the <code>kIOInterfaceFlags</code>
    property using the provided value. See <code>bsd/net/if.h</code> header
    file for the flag constants.
    @param flags The bits that should be set.
    @param clear The bits that should be cleared. If zero, then non
    of the flags are cleared and the result is formed by OR'ing the
    original flags value with the new flags.
    @result Always returns true.
*/
    virtual bool     setFlags( UInt16 flags, UInt16 clear = 0 );

    /* Deprecated. No replacement. */
    virtual bool     setExtraFlags( UInt32 flags, UInt32 clear = 0 );

/*! @function setMediaAddressLength
    @abstract Sets the size of the media (MAC-layer) address.
    @discussion Calls <code>ifnet_set_addrlen</code> if interface is attached
    to the network stack, and updates the <code>kIOMediaAddressLength</code>
    property using the provided value.
    @param length The size of the media address in bytes.
    @result Always returns true.
*/
    virtual bool     setMediaAddressLength( UInt8 length );

/*! @function setMediaHeaderLength
    @abstract Sets the size of the media header.
    @discussion Calls <code>ifnet_set_hdrlen</code> if interface is attached
    to the network stack, and updates the <code>kIOMediaHeaderLength</code>
    property using the provided value.
    @param length The size of the media header in bytes.
    @result Always returns true.
*/
    virtual bool     setMediaHeaderLength( UInt8 length );

/*! @function setUnitNumber
    @abstract Assigns an unique unit number to this interface.
    @discussion This method is called internally before the interface is
    attached to the network stack, to assign an unique unit number to the
    interface object. The <code>kIOInterfaceUnit</code> property is also
    updated using the provided value.
    @param unit The unit number assigned to this interface object.
    @result Returns true to indicate success if the interface has not yet
    attached to the network stack, otherwise returns false.
*/
    virtual bool     setUnitNumber( UInt16 unit );

/*! @function free
    @abstract Frees the <code>IONetworkInterface</code> object.
    @discussion Resource allocated by init() are released, and
    clearInputQueue() is called to ensure that the input queue is empty.
    The interface should have already detached from the network stack.
*/
    virtual void     free( void );

    /* Override IOService::handleOpen() */
    virtual bool     handleOpen( IOService *  client,
                                 IOOptionBits options,
                                 void *       argument );

    /* Override IOService::handleClose() */
    virtual void     handleClose( IOService * client, IOOptionBits options );

    /* Override IOService::handleIsOpen() */
    virtual bool     handleIsOpen( const IOService * client ) const;

/*! @function lock
    @abstract Acquires a recursive lock owned by the interface.
    @discussion A recursive lock is allocated and initialized in
    <code>init()</code>. This lock is otherwise not used by the
    <code>IONetworkInterface</code> class. This method call acquires
    the lock and must be balanced with an <code>unlock()</code>.
*/
    virtual void     lock( void );

/*! @function unlock
    @abstract Releases the recursive lock owned by the interface.
    @discussion A recursive lock is allocated and initialized in
    <code>init()</code>. This lock is otherwise not used by the
    <code>IONetworkInterface</code> class. This method call releases
    the lock to balance a prior <code>lock()</code>.
*/
    virtual void     unlock( void );

/*! @function controllerDidOpen
    @abstract Sends a notification that the interface has opened the network
    controller.
    @discussion This method is called by <code>handleOpen()</code> to notify
    subclasses that the controller was opened. The open on the controller
    occurs when the interface receives the initial open request from a client.
    Subclasses can override this method and inspect the controller before
    allowing the client open. This method is called with the arbitration lock
    held, hence issuing I/O to the controller must be avoided to eliminate the
    possibility of a deadlock.
    @param controller The controller that was opened.
    @result Must return true in order for handleOpen() to accept the client
    open. If the return is false, then the controller will be closed and the
    client open will fail.
*/
    virtual bool     controllerDidOpen( IONetworkController * controller );

/*! @function controllerWillClose
    @abstract Sends a notification that the interface will close the network
    controller.
    @discussion This method is called by <code>handleClose()</code> after
    receiving a close from the last interface client, and just before the
    controller is closed. Subclasses can override this method to perform any
    cleanup action before the controller is closed. This method is called with
    the arbitration lock held, hence issuing I/O to the controller should be
    avoided to eliminate the possibility of a deadlock.
    @param controller The controller that is about to be closed.
*/
    virtual void     controllerWillClose( IONetworkController * controller );

/*! @function performCommand
    @abstract Handles an ioctl command sent to the network interface.
    @discussion This method handles socket ioctl commands sent to the
    network interface from DLIL.
    IONetworkInterface handles commands that are common for all network
    interface types. A subclass of IONetworkInterface may override this
    method to override the command handling in IONetworkInterface, or
    to extend the command processing to handle additional commands.
    The ioctl commands handled by IONetworkInterface are
        <code>SIOCGIFMTU</code> (Get interface MTU size),
        <code>SIOCSIFMTU</code> (Set interface MTU size),
        <code>SIOCSIFMEDIA</code> (Set media), and
        <code>SIOCGIFMEDIA</code> (Get media and link status).
    @param controller The controller object.
    @param cmd The ioctl command code.
    @param arg0 Command argument 0. Generally a pointer to an ifnet structure
        associated with the interface.
    @param arg1 Command argument 1.
    @result Returns a BSD return value defined in <code>bsd/sys/errno.h</code>.
*/
    virtual SInt32   performCommand(
                                IONetworkController * controller,
                                unsigned long         cmd,
                                void *                arg0,
                                void *                arg1 );

public:

/*! @function getIfnet
    @abstract Returns the <code>ifnet_t</code> allocated by the interface object.
    @discussion Gets the interface's <code>ifnet_t</code>, which is managed
    primarily by <code>IONetworkInterface</code>, however subclasses or drivers
    can use this method to obtain a reference to the <code>ifnet_t</code> for
    interface KPI calls.
    @result Returns the <code>ifnet_t</code> after the interface has attached
    to the network stack and before the interface is detached, otherwise returns
    NULL.
*/
    virtual ifnet_t  getIfnet( void ) const;

protected:

    /* Deprecated. Use <code>initIfnetParams</code> instead. */
    virtual bool     initIfnet( struct ifnet * ifp );

/*! @function handleClientOpen
    @abstract Handles a client open on the interface.
    @discussion This method is called by <code>handleOpen()</code> to allow a
    subclass to handle a client close. The arbitration lock is held.
    @param client The client object requesting the open.
    @param options Options passed to <code>handleOpen()</code>.
    @param argument Argument passed to <code>handleOpen()</code>.
    @result Returns true to accept the client open, false to reject the open.
*/
    virtual bool     handleClientOpen( IOService *  client,
                                       IOOptionBits options,
                                       void *       argument );

/*! @function handleClientClose
    @abstract Handles a client close on the interface.
    @discussion This method is called by <code>handleClose()</code> to allow a
    subclass to handle a client close. The arbitration lock is held.
    @param client The client object requesting the close.
    @param options Options same options passed to <code>handleClose()</code>.
*/
    virtual void     handleClientClose( IOService *  client,
                                        IOOptionBits options );

    /* Override IOService::newUserClient() */
    virtual IOReturn newUserClient( task_t           owningTask,
                                    void *           security_id,
                                    UInt32           type,
                                    IOUserClient **  handler );

/*! @function setInterfaceState
    @abstract Updates the interface object state flags.
    @discussion The flags reflect the current state of the interface, and is
    also published through the <code>kIOInterfaceState</code> property.
    @param set The flags that should be set.
    @param clear The flags that should be cleared.
    @result Returns the new interface state flags.
*/
    virtual UInt32   setInterfaceState( UInt32 set, UInt32 clear = 0 );

/*! @function powerStateWillChangeTo
    @abstract Handles a pre-change power interest notification from the
    network controller.
    @discussion The <code>controllerWillChangePowerState()</code> method is
    called by this handler. Subclasses are not expected to override this method.
    @param flags Flags that describe the capability of the controller in the
    new power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller is switching to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result Returns <code>IOPMAckImplied</code> to indicate synchronous completion.
*/
    virtual IOReturn powerStateWillChangeTo(
                                IOPMPowerFlags  flags,
                                unsigned long   stateNumber,
                                IOService *     policyMaker );

/*! @function powerStateDidChangeTo
    @abstract Handles a post-change power interest notification from the
    network controller.
    @discussion The <code>controllerDidChangePowerState()</code> method is
    called by this handler. Subclasses are not expected to override this method.
    @param flags Flags that describe the capability of the controller in the
    new power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller has switched to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result Returns <code>IOPMAckImplied</code> to indicate synchronous completion.
*/
    virtual IOReturn powerStateDidChangeTo(
                                IOPMPowerFlags  flags,
                                unsigned long   stateNumber,
                                IOService *     policyMaker );

/*! @function controllerWillChangePowerState
    @abstract Handles a notification that the network controller servicing
    this interface object will transition to a new power state.
    @param controller The network controller object.
    @param flags Flags that describe the capability of the controller in the
    new power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller is switching to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return value is always <code>kIOReturnSuccess</code>.
*/
    virtual IOReturn controllerWillChangePowerState(
                                IONetworkController * controller,
                                IOPMPowerFlags        flags,
                                UInt32                stateNumber,
                                IOService *           policyMaker );

/*! @function controllerDidChangePowerState
    @abstract Handles a notification that the network controller servicing
    this interface object has transitioned to a new power state.
    @param controller The network controller object.
    @param flags Flags that describe the capability of the controller in the
    new power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller has switched to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return value is always <code>kIOReturnSuccess</code>.
*/
    virtual IOReturn controllerDidChangePowerState(
                                IONetworkController * controller,
                                IOPMPowerFlags        flags,
                                UInt32                stateNumber,
                                IOService *           policyMaker );

public:
    /* Override IOService::willTerminate() */
    virtual bool     willTerminate(
                                IOService *  provider,
                                IOOptionBits options );

    /* Override IOService::requestTerminate() */
    virtual bool     requestTerminate(
                                IOService * provider, IOOptionBits options );

    /* Override IOService::serializeProperties() */
    virtual bool     serializeProperties( OSSerialize * s ) const;

/*! @function attachToDataLinkLayer
    @abstract Attach the network interface to the BSD data link layer.
    @discussion This method is called internally to attach the network
    interface to the BSD data link layer, after an unit number has been
    assigned. The calling context is not synchronized against the driver's
    work loop. Subclasses may override this method to perform additional
    setup before the network stack attach. The <code>getIfnet()</code> method
    will return the BSD interface being attached.
    @param options Options for the attach call. None are currently defined.
    @param parameter Parameter for the attach call. Not currently used.
    @result Returns <code>kIOReturnSuccess</code> on success.
*/
    virtual IOReturn attachToDataLinkLayer( IOOptionBits options,
                                            void *       parameter );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 0);

/*! @function detachFromDataLinkLayer
    @abstract Detach the network interface from the BSD data link layer.
    @discussion This method is called internally to detach the network
    interface from the BSD data link layer, after the interface has been
    terminated and before the last client close. This method will block until
    the detach operation is complete. The calling context is not synchronized
    against the driver's work loop. Subclasses may override this method to
    perform additional cleanup before or after detaching from the network
    stack. The <code>getIfnet()</code> method will return NULL after detach.
    @param options Options for the detach call. None are currently defined.
    @param parameter Parameter for the detach call. Not currently used.
*/
    virtual void     detachFromDataLinkLayer( IOOptionBits options,
                                              void *       parameter );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 1);

protected:
/*! @function feedPacketInputTap
    @abstract Feed received packets to the BPF
    @discussion This function is called internally to send input packets to
    the BPF input tap when it is enabled. Subclasses are not expected to
    override this method.
    @param mbuf_t Pointer to the input packet.
*/
    virtual void     feedPacketInputTap( mbuf_t );

	OSMetaClassDeclareReservedUsed(IONetworkInterface, 2);

/*! @function feedPacketOutputTap
    @abstract Feed output packets to the BPF
    @discussion This function is called internally to send output packets to
    the BPF output tap when it is enabled. Subclasses are not expected to
    override this method.
    @param mbuf_t Pointer to the output packet.
*/
	virtual void     feedPacketOutputTap( mbuf_t );

	OSMetaClassDeclareReservedUsed(IONetworkInterface, 3);

/*! @function initIfnetParams
    @abstract Allows a subclass to provide ifnet initialization parameters
    specific to an interface type.
    @discussion This method initializes the parameters that are common to all
    network interfaces. An interface subclass is expected to override this
    method, call the superclass implementation first, then initialize the
    parameters specific to that interface type. This method is called after
    an unit number has been assigned to the interface, and just before the
    interface is attached to BSD.
    @param params Pointer to an <code>ifnet_init_params</code> allocated by
    the caller.
    @result Returns <code>true</code> on success, <code>false</code> otherwise.
*/
	virtual bool     initIfnetParams( struct ifnet_init_params * params );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 4);

public:
#ifdef __PRIVATE_SPI__
/*! @function setInterfaceSubType
    @abstract Sets the interface sub-type.
    @discussion The sub-type must be set before the interface is attached to
    the networking stack. The driver's <code>configureInterface()</code>
    or <code>attachToDataLinkLayer</code> in a subclass are valid call sites.
    @param subType A constant defined in <code>IONetworkTypesPrivate.h</code>.
    @result Returns <code>true</code> on success, <code>false</code> otherwise.
*/
    bool    setInterfaceSubType( uint32_t subType );

/*! @function isBPFTapEnabled
    @abstract Query if the BPF tap is enabled.
    @abstract Allows a driver to poll the BPF tap state after receiving a
    <code>kIONetworkNotificationBPFTapStateChange</code> notification.
    @param options No options are currently defined, always pass zero.
    @result Returns <code>true</code> if BPF tap is enabled,
    <code>false</code> otherwise.
*/
    bool    isBPFTapEnabled( IOOptionBits options = 0 ) const;

/*! @function getLoggingLevel
    @abstract Query the logging level for the interface.
    @abstract Allows a driver to poll the logging level after receiving a
    <code>kIONetworkNotificationLoggingLevelChange</code> notification.
    @param options No options are currently defined, always pass zero.
    @result Returns the current logging level.
*/
    int32_t getLoggingLevel( IOOptionBits options = 0 ) const;

/*! @enum OutputPacketSchedulingModel
    @discussion Output packet scheduling models.
    @constant kOutputPacketSchedulingModelNormal
    The default output packet scheduling model where the driver or media does
    not require strict scheduling strategy, and that the networking stack is
    free to choose the most appropriate scheduling and queueing algorithm,
    including shaping traffics.
    @constant kOutputPacketSchedulingModelDriverManaged
    The alternative output packet scheduling model where the driver or media
    requires strict scheduling strategy (e.g. 802.11 WMM), and that the
    networking stack is only responsible for creating multiple queues for the
    corresponding service classes.
*/
    enum {
        kOutputPacketSchedulingModelNormal          = 0,
        kOutputPacketSchedulingModelDriverManaged   = 1
    };

/*! @function configureOutputPullModel
    @abstract Configure and use the pull-model to transmit packets.
    @discussion A driver that supports the pull-model to transmit packets must
    call this method from <code>configureInterface()</code> to configure the
    model, and to transition the interface to use the pull-model exclusively.
    In the pull-model, the interface will manage an output queue that a driver
    can pull packets from. An output thread will notify the driver through
    <code>outputStart()</code> when packets are added to the output queue.
    @param driverQueueSize The number of packets that the driver's transmit
    queue or ring can hold.
    @param options <code>kIONetworkWorkLoopSynchronous</code> forces the output
    thread to call <code>outputStart()</code> on the driver's work loop context.
    @param outputQueueSize The size of the interface output queue. Unless the
    driver has special requirements, it is advisable to pass zero to let the
    networking stack choose the output queue size.
    @param outputSchedulingModel An output packet scheduling model.
    Pass zero or <code>kOutputPacketSchedulingModelNormal</code> for the default
    model which lets the network stacking choose the most appropriate scheduling
    and queueing algorithm.
    @result <code>kIOReturnSuccess</code> if interface was successfully
    configured to use the pull-model for outbound packets.
*/
    virtual IOReturn configureOutputPullModel(
                            uint32_t       driverQueueSize,
                            IOOptionBits   options               = 0,
                            uint32_t       outputQueueSize       = 0,
                            uint32_t       outputSchedulingModel = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 5);

/*! @function configureInputPacketPolling
    @abstract Configure and enable polling of input packets.    
    @discussion A driver that supports polled-mode processing of input packets
    must call this method from <code>configureInterface()</code> to configure
    input polling. Once configured, the network stack is allowed to dynamically
    transition the input model from the default push-model where packets are
    pushed by the driver to the network stack, to the pull-model where a poller
    thread will periodically pull packets (if any) from the driver.
    @param driverQueueSize The number of packets that the driver's receive
    queue or ring can hold when completely full.
    @param options <code>kIONetworkWorkLoopSynchronous</code> forces the
    poller thread to call <code>pollInputPackets()</code> on the driver's
    work loop context. The <code>setInputPacketPollingEnable()</code>
    method call is always synchronized against the driver's work loop.
    @result <code>kIOReturnSuccess</code> if input polling was successfully
    configured.
*/
    virtual IOReturn configureInputPacketPolling(
                            uint32_t       driverQueueSize,
                            IOOptionBits   options = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 6);

/*! @function reportDataTransferRates
    @abstract For drivers to report the current data transfer rates.
    @discussion The rates reported by this method will supersede the single
    link speed reported by <code>IONetworkController::setLinkStatus</code>.
    This method allows the driver to report asymmetric input and output data
    rates, and also the effective data rates when available. 
    @param outputRateMax The maximum output data rate in bit/s.
    @param inputRateMax The maximum input data rate in bit/s.
    @param outputRateEffective The effective output data rate in bit/s.
    If zero, the outputRateMax value is passed to the network stack.
    @param inputRateEffective The effective input data rate in bit/s.
    If zero, the inputRateMax value is passed to the network stack.
*/
    virtual void     reportDataTransferRates(
                            uint64_t    outputRateMax,
                            uint64_t    inputRateMax,
                            uint64_t    outputRateEffective = 0,
                            uint64_t    inputRateEffective  = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 7);

/*! @function stopOutputThread
	@abstract Called by drivers to stop the output thread.
	@discussion Only drivers that support the pull output model should call
    this method. In the stop state, the output thread will not invoke the
    driver's <code>outputStart()</code> method, even when new packets are
    added to the output queue. This method is synchronous with respect to
    any <code>outputStart()</code> invocation, so upon returning from this
    method it is guaranteed that the output thread has stopped executing
    driver code. The network interface will internally stop the output
    thread before detaching from the network stack, and also before system
    shutdown and restart.
	@param options No options are currently defined, always pass zero.
    @result <code>kIOReturnSuccess</code> if the thread was stopped,
    <code>kIOReturnTimeout</code> if the wait for output thread to exit
    <code>outputStart()</code> timed out.
*/
    IOReturn         stopOutputThread( IOOptionBits options = 0 );

/*! @function startOutputThread
	@abstract Called by drivers to start the output thread.
	@discussion The output thread is initially in a stop state, and it must
    be started before it can invoke the driver's <code>outputStart()</code>
    method. Drivers may also issue start to release a previous stop request.
    After starting the output thread, if the output queue is not empty, or
    after a new packet is added to the output queue, the output thread will
    wakeup and invoke the driver's <code>outputStart()</code> method.
	@param options No options are currently defined, always pass zero.
    @result <code>kIOReturnSuccess</code> if start was successful,
    <code>kIOReturnNotAttached</code> if the network interface has detached
    from the network stack.
*/
    IOReturn         startOutputThread( IOOptionBits options = 0 );

/*! @function signalOutputThread
	@abstract Informs the output thread that driver has completed packet
    transmission.
	@discussion A driver that supports the pull output model must call this
    method after packet transmission is complete, and driver resources are
    available to <code>outputStart()</code> to handle additional packets.
    It is recommended to batch this call when retiring a group of output
    packets. This method will wake up the output thread if the output queue
    is not empty, and the output thread is not stopped.
	@param options No options are currently defined, always pass zero.
*/
    void             signalOutputThread( IOOptionBits options = 0 );

/*! @function flushOutputQueue
	@abstract Flush all packets in the interface output queue.
	@discussion A driver that supports the pull output model can use this
    method to free all packets currently held in the interface output queue.
	@param options No options are currently defined, always pass zero.
*/
    void             flushOutputQueue( IOOptionBits options = 0 );

/*! @function dequeueOutputPackets
	@abstract Dequeue packets from the interface output queue.
	@discussion A driver that supports the output pull-model will typically
    call this method from <code>outputStart()</code> after it has calculated
    the maximum number of packets that can be dequeued based on available
    resources. Drivers should not dequeue more packets than they can accept
    since there is no facility to insert a packet to the head of the queue.
    The only recourse is to drop the packet, or store the packet on a driver
    managed queue which is not recommended. This method can dequeue a single
    packet as a mbuf chain, or multiple packets using a linked list of mbuf
    chains. It is also possible for the queue to not return any packet to the
    driver in order to throttle the transmit rate. Although typically called
    from <code>outputStart()</code>, this is not a mandatory requirement. E.g.
    a driver may choose to dequeue in the transmit completion path to quickly
    fill an available transmit slot.
    @param maxCount The maximum number of packets to dequeue. This value must
    be greater than zero.
    @param packetHead Pointer to the first packet that was dequeued.
    @param packetTail Optional pointer to the last packet that was dequeued.
	@param packetCount Optional pointer to store the number of packets that
    was dequeued.
	@param packetBytes Optional pointer to store the total length of packets
    that was dequeued. The length of each packet is given by
    <code>mbuf_pkthdr_len()</code>.
	@result <code>kIOReturnSuccess</code> if at least one packet was dequeued,
	<code>kIOReturnBadArgument</code> if an argument was invalid,
    <code>kIOReturnNoFrames</code> if the queue is empty, or the queue is
    limiting the transmit rate.
*/
    virtual IOReturn dequeueOutputPackets(
                            uint32_t            maxCount,
                            mbuf_t *            packetHead,
                            mbuf_t *            packetTail  = 0,
                            uint32_t *          packetCount = 0,
                            uint64_t *          packetBytes = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 8);

/*! @function dequeueOutputPacketsWithServiceClass
	@abstract Dequeue packets of a particular service class from the interface
    output queue.
    @discussion See <code>dequeueOutputPackets</code>.
    @param maxCount The maximum number of packets to dequeue. This value must
    be greater than zero.
    @param serviceClass A service class specification provided by the caller.
    Only packets belonging to the specified service class will be dequeued.
    @param packetHead Pointer to the first packet that was dequeued.
    @param packetTail Optional pointer to the last packet that was dequeued.
	@param packetCount Optional pointer to store the number of packets that
    was dequeued.
	@param packetBytes Optional pointer to store the total length of packets
    that was dequeued. The length of each packet is given by
    <code>mbuf_pkthdr_len()</code>.
	@result <code>kIOReturnSuccess</code> if at least one packet was dequeued,
	<code>kIOReturnBadArgument</code> if an argument was invalid,
    <code>kIOReturnNoFrames</code> if the queue is empty, no packet belongs to
    the service class or the queue is limiting the transmit rate.
*/
    virtual IOReturn dequeueOutputPacketsWithServiceClass(
                            uint32_t            maxCount,
                            IOMbufServiceClass  serviceClass,
                            mbuf_t *            packetHead,
                            mbuf_t *            packetTail  = 0,
                            uint32_t *          packetCount = 0,
                            uint64_t *          packetBytes = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 9);

/*  @function installOutputPreEnqueueHandler
    @abstract Install a handler to intercept all output packets before they
    are added to the output queue.
    @discussion A single handler can be installed before the interface is
    attached to the networking stack. The handler will not be invoked unless
    the driver configures the interface to utilize the new output pull-model.
    @param handler A C-function handler.
    @target A reference passed to the handler.
    @refCon A reference constant passed to the handler.
    @result <code>kIOReturnSuccess</code> if the handler was successfully
    installed, <code>kIOReturnBadArgument</code> if the handler provided was
    NULL, or <code>kIOReturnError</code> if the call was made after the
    interface has already attached to the networking stack.
*/
    IOReturn         installOutputPreEnqueueHandler(
                            OutputPreEnqueueHandler handler,
                            void *                  target,
                            void *                  refCon );

/* @function enqueueOutputPacket
   @abstract Enqueue a packet to the output queue.
   @discussion Wrapper for the private <code>ifnet_enqueue()</code>.
   @param packet The packet being enqueued; only one packet is allowed
   to be enqueued at a time.
   @param options No options are currently defined, always pass zero.
   @result The value returned by <code>ifnet_enqueue()</code>.
*/
    errno_t          enqueueOutputPacket(
                            mbuf_t          packet,
                            IOOptionBits    options = 0 );

/*! @function enqueueInputPacket
    @abstract Queue a packet received by the driver before forwarding it to
    the networking stack.
    @discussion When input polling is not enabled, drivers should call this
    method to queue each received packet on the interface input queue, then
    flush the input queue at the end of the driver receive loop. When this
    method is called as a result of input polling, driver must specify the
    polling queue by passing the queue provided by the poller. Access to the
    interface input queue is unsynchronized, since input packet handling is
    expected to be single-threaded. The input packet must point to a header
    mbuf with <code>MBUF_PKTHDR</code> flag set, with any additional mbufs
    linked by the next chain. The length in the packet header, including the
    data length for every mbuf in the chain must be set. If FCS is included
    in the packet data, then the <code>MBUF_HASFCS</code> mbuf flag must be
    set. This is the preferred interface to queue and submit an input packet,
    and is functionally equivalent to calling <code>inputPacket</code> with
    the <code>kInputOptionQueuePacket</code> option. Submitting a chain of
    packets is not supported. 
    @param packet The input packet. Caller ceases ownership of the packet
    regardless of the return value.
    @param queue Defaults to zero which specifies the interface input queue.
    To handoff a packet during input polling, pass the queue provided by the
    poller.
	@param options No options are currently defined, always pass zero.
	@result <code>kIOReturnSuccess</code> if packet was added to the queue,
    or an error code otherwise.
*/
    virtual IOReturn enqueueInputPacket(
                            mbuf_t          packet,
                            IOMbufQueue *   queue   = 0,
                            IOOptionBits    options = 0 );

    OSMetaClassDeclareReservedUsed(IONetworkInterface, 10);

/*! @function reportTransmitCompletionStatus
    @abstract Report the transmit completion status for an outgoing packet.
    @discussion Invoked by drivers that are capable of reporting when a packet
    has been transmitted across the link layer. Besides reporting the packet
    transmit status using this method, driver must also publish the
    <code>kIONetworkFeatureTransmitCompletionStatus</code> feature.
    @param packet The packet that was transmitted.
    @param status The transmit status.
    @param param1 Always pass zero.
    @param param2 Always pass zero.
    @param No options are currently defined, always pass zero.
    @result <code>kIOReturnSuccess</code> if the transmit status was valid
    and accepted, otherwise <code>kIOReturnBadArgument</code> for bad status,
    or <code>kIOReturnError</code> if an error occurred when passing the status
    to the networking stack.
*/
    IOReturn reportTransmitCompletionStatus(
                            mbuf_t                  packet,
                            IOReturn                status,
                            uint32_t                param1  = 0,
                            uint32_t                param2  = 0,
                            IOOptionBits            options = 0 );

/*! @function reportDatapathIssue
    @abstract Used by kernel network driver or family to inform userspace
    of a datapath issue.
    @discussion An issue report will be sent to any userspace applications
    or daemons that have registered for datapath issues notifications from
    this network interface.
    @param issue Subsystem specific error code.
    @param data Reserved for future use.
    @param length Reserved for future use.
    @result Returns <code>kIOReturnSuccess</code> if successful,
    otherwise an appropriate error code.
*/
    IOReturn reportDatapathIssue(
                            IOReturn 	issue,
                            void * 		data   = 0,
                            IOByteCount length = 0 );

/*! @function setPacketPollingParameters
    @abstract Modify the input polling parameters.
    @discussion Invokes <code>ifnet_set_poll_params()</code> using the
    parameters provided.
    @param params Polling parameters.
    @param options No options are currently defined, always pass zero.
    @result Returns <code>kIOReturnSuccess</code> if successful,
    otherwise an appropriate error code.
*/
    IOReturn setPacketPollingParameters(
                            const IONetworkPacketPollingParameters * params,
                            IOOptionBits options = 0 );
#else   /* !__PRIVATE_SPI__ */
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  5);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  6);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  7);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  8);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  9);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 10);
#endif  /* !__PRIVATE_SPI__ */
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 11);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 12);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 13);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 14);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 15);
};

#endif /* __cplusplus */
#endif /* KERNEL */
#endif /* !_IONETWORKINTERFACE_H */
