#ifndef AIRPORTITLWM_SEQUOIA_HPP
#define AIRPORTITLWM_SEQUOIA_HPP

#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/locks.h>

#include "IOPCIEDeviceWrapper.hpp"
#include "FirmwareLoader.hpp"
#include "AirportItlwmSkywalkInterface.hpp"  // Skywalk integration header

class IONetworkInterface;
class IOWorkLoop;
class IOGatedOutputQueue;

class AirportItlwm_Sequoia : public IOService {
    OSDeclareDefaultStructors(AirportItlwm_Sequoia)

private:
    AirportItlwmSkywalkInterface *skywalkInterface;  // Skywalk interface instance

public:
    virtual bool init(OSDictionary *properties) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual void free() override;

    void connectToNetwork(uint8_t *ssid, uint32_t ssid_len, uint8_t *bssid, uint32_t auth_type, uint8_t *key, uint32_t key_len);
    void setSecurityKeys(uint8_t *ptk, size_t ptk_len, uint8_t *gtk, size_t gtk_len);
};

#endif /* AIRPORTITLWM_SEQUOIA_HPP */
