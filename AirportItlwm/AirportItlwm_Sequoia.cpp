#include "AirportItlwm_Sequoia.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <sys/sysctl.h>

#define super IOService
OSDefineMetaClassAndStructors(AirportItlwm_Sequoia, IOService);

#define DRVLOG(fmt, ...) IOLog("[AirportItlwm Sequoia v" AIRPORTITLWM_VERSION "] " fmt "\n", ##__VA_ARGS__)
#define DRVINFO(fmt, ...) IOLog("[AirportItlwm Sequoia INFO] " fmt "\n", ##__VA_ARGS__)
#define DRVERR(fmt, ...) IOLog("[AirportItlwm Sequoia ERROR] " fmt "\n", ##__VA_ARGS__)
#define DRWARN(fmt, ...) IOLog("[AirportItlwm Sequoia WARN] " fmt "\n", ##__VA_ARGS__)

bool AirportItlwm_Sequoia::init(OSDictionary *properties) {
    if (!super::init(properties)) {
        DRVERR("Failed to initialize super class");
        return false;
    }

    // Create Skywalk interface
    skywalkInterface = new AirportItlwmSkywalkInterface();
    if (!skywalkInterface) {
        DRVERR("Failed to create Skywalk interface");
        return false;
    }

    DRVINFO("Skywalk interface initialized successfully");
    return true;
}

bool AirportItlwm_Sequoia::start(IOService *provider) {
    if (!super::start(provider)) {
        DRVERR("Failed to start super class");
        return false;
    }

    // Initialize Skywalk interface
    if (skywalkInterface && !skywalkInterface->init(this)) {
        DRVERR("Failed to initialize Skywalk interface");
        return false;
    }

    DRVINFO("Skywalk interface started");
    return true;
}

void AirportItlwm_Sequoia::stop(IOService *provider) {
    if (skywalkInterface) {
        skywalkInterface->release();
        skywalkInterface = nullptr;
    }
    super::stop(provider);
}

void AirportItlwm_Sequoia::free() {
    super::free();
    if (skywalkInterface) {
        skywalkInterface->release();
    }
}

void AirportItlwm_Sequoia::connectToNetwork(uint8_t *ssid, uint32_t ssid_len, uint8_t *bssid, uint32_t auth_type, uint8_t *key, uint32_t key_len) {
    // Associate with Wi-Fi network using Skywalk
    if (skywalkInterface) {
        skywalkInterface->associateSSID(ssid, ssid_len, bssid, auth_type, 0, key, key_len);
    }
}

void AirportItlwm_Sequoia::setSecurityKeys(uint8_t *ptk, size_t ptk_len, uint8_t *gtk, size_t gtk_len) {
    // Set PTK and GTK keys for security
    if (skywalkInterface) {
        skywalkInterface->setPTK(ptk, ptk_len);
        skywalkInterface->setGTK(gtk, gtk_len, 0, nullptr);
    }
}
