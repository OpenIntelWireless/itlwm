/* add your code here */
#include "compat.h"
#include "if_iwmreg.h"
#include "if_iwmvar.h"

#include <IOKit/network/IOEthernetController.h>
#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>

OSDefineMetaClassAndStructors(CTimeout, OSObject)

class itlwm : public IOEthernetController {
    OSDeclareDefaultStructors(itlwm)
    
public:
    //kext
    bool init(OSDictionary *properties) override;
    void free() override;
    IOService* probe(IOService* provider, SInt32* score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    IOReturn setPromiscuousMode(bool active) override;
    IOReturn setMulticastMode(bool active) override;
    IOOutputQueue * createOutputQueue() override;
    UInt32 outputPacket(mbuf_t, void * param) override;

    
};
