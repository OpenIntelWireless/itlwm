//
//  AirportItlwmSkywalkInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//
#include "ItlCountedCopy.hpp"
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#if defined(ITL_AWDL_NATIVE)
#include "AirportAWDLInterface.hpp"
#endif
#include <sys/CTimeout.hpp>
#include <libkern/c++/OSMetaClass.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>

#ifdef AIRPORT_WCL
extern IOCommandGate *_fCommandGate;
#endif

#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(AirportItlwmSkywalkInterface, IO80211InfraProtocol);

const char* hexdump(uint8_t *buf, size_t len) {
    ssize_t str_len = len * 3 + 1;
    char *str = (char*)IOMalloc(str_len);
    if (!str)
        return nullptr;
    for (size_t i = 0; i < len; i++)
    snprintf(str + 3 * i, (len - i) * 3, "%02x ", buf[i]);
    str[MAX(str_len - 2, 0)] = 0;
    return str;
}

static int ieeeChanFlag2appleScanFlagVentura(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    ret |= (APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ);
    return ret;
}

static int ieeeChanFlag2apple(int flags, int bw)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))
        ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_DFS)
        ret |= APPLE80211_C_FLAG_DFS;
    if (bw == -1) {
        if (flags & IEEE80211_CHAN_VHT) {
            if ((flags & IEEE80211_CHAN_VHT160) || (flags & IEEE80211_CHAN_VHT80_80))
                ret |= APPLE80211_C_FLAG_160MHZ;
            if (flags & IEEE80211_CHAN_VHT80)
                ret |= APPLE80211_C_FLAG_80MHZ;
        } else if ((flags & IEEE80211_CHAN_HT40) && (flags & IEEE80211_CHAN_HT)) {
            ret |= APPLE80211_C_FLAG_40MHZ;
            if (flags & IEEE80211_CHAN_HT40U)
                ret |= APPLE80211_C_FLAG_EXT_ABV;
        } else if (flags & IEEE80211_CHAN_HT20)
            ret |= APPLE80211_C_FLAG_20MHZ;
        else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
            ret |= APPLE80211_C_FLAG_10MHZ;
    } else {
        switch (bw) {
            case IEEE80211_CHAN_WIDTH_80P80:
            case IEEE80211_CHAN_WIDTH_160:
                ret |= APPLE80211_C_FLAG_160MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_80:
                ret |= APPLE80211_C_FLAG_80MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_40:
                ret |= APPLE80211_C_FLAG_40MHZ;
                if (flags & IEEE80211_CHAN_HT40U)
                    ret |= APPLE80211_C_FLAG_EXT_ABV;
                break;
            case IEEE80211_CHAN_WIDTH_20:
                ret |= APPLE80211_C_FLAG_20MHZ;
                break;
            default:
                if (flags & IEEE80211_CHAN_HT20)
                    ret |= APPLE80211_C_FLAG_20MHZ;
                else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
                    ret |= APPLE80211_C_FLAG_10MHZ;
                break;
        }
    }
    return ret;
}

// The auth type a join request is handled as. This build doesn't support WPA3; it announces it in the
// card capabilities and joins WPA2/WPA3 transition networks as WPA2.
static uint32_t effectiveAuthUpper(uint32_t authtype_upper)
{
#ifndef AIRPORT_WCL
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_SAE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_SAE)
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK;
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_ENTERPRISE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE)
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2;
#endif
    return authtype_upper;
}

// Every reason to refuse a join, checked before anything is changed (audit F01): a refusal halfway
// through used to leave RSN off and the new SSID set, so the driver would join an open network of that
// name. Caller lengths are copied into fixed fields: the SSID into 32 bytes, the PSK as exactly 32 bytes
// (P-R04), the WEP key index into a 4-entry array.
static bool associateRequestValid(const uint8_t *ssid, uint32_t ssid_len, uint32_t authtype_lower, uint32_t authtype_upper,
                                  const uint8_t *key, uint32_t key_len, int key_index)
{
    if ((ssid_len && !ssid) || ssid_len > IEEE80211_NWID_LEN || key_len > APPLE80211_KEY_BUFF_LEN ||
        (key_len && !key) || key_index < 0 || key_index >= IEEE80211_WEP_NKID) {
        XYLog("associateSSID: refused, ssid_len=%u key_len=%u key_index=%d\n", ssid_len, key_len, key_index);
        return false;
    }
    if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
        XYLog("associateSSID: refused, shared key authentication is not supported\n");
        return false;
    }
    const uint32_t upper = effectiveAuthUpper(authtype_upper);
    if ((upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) &&
        (!key || key_len != 32)) {
        XYLog("associateSSID: PSK refused, key_len=%u\n", key_len);
        return false;
    }
    return true;
}

IOReturn AirportItlwmSkywalkInterface::associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    static_assert(sizeof(ic->ic_psk) == 32, "PMK size");
    if (!ic || !associateRequestValid(ssid, ssid_len, authtype_lower, authtype_upper, key, key_len, key_index))
        return kIOReturnBadArgument;

    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    // Don't leave the previous network's PMK behind (the WCL join path clears it the same way).
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    ic->ic_flags &= ~IEEE80211_F_PSK;

    struct ieee80211_wpaparams     wpa;
    struct ieee80211_nwkey         nwkey;
    bzero(&wpa, sizeof(wpa));
    bzero(&nwkey, sizeof(nwkey));

    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssid_len);
    ic->ic_des_esslen = ssid_len;

    bool is_zero = true;
    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
    is_zero &= bssid.octet[i] == 0;

    if (!is_zero) {
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
        ic->ic_flags |= IEEE80211_F_DESBSSID;
    }
    else {
        memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);
        ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    }

    const uint32_t requestedUpper = authtype_upper;
    authtype_upper = effectiveAuthUpper(authtype_upper);
    if (authtype_upper != requestedUpper)
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    }

    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        // associateRequestValid checked that the key is exactly the 32-byte PMK (audit P-R04).
        wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;
        wpa.i_enabled = 1;
        memcpy(ic->ic_psk, key, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_enabled = 1;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }

    if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
        if (key_len > 0) {
            XYLog("%s %d\n", __FUNCTION__, __LINE__);
            nwkey.i_wepon = IEEE80211_NWKEY_WEP;
            nwkey.i_defkid = key_index + 1;
            nwkey.i_key[key_index].i_keylen = (int)key_len;
            nwkey.i_key[key_index].i_keydat = key;
            ieee80211_ioctl_setnwkeys(ic, &nwkey);
        }
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::setPTK(const u_int8_t *key, size_t key_len) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;

    ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;

    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        u_int64_t prsc;

        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (keylen < 0 || key_len != (size_t)keylen) {
            XYLog("PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;

        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, key, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            XYLog("setting PTK failed\n");
            return;
        }
        else
            XYLog("setting PTK successfully\n");
        ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    } else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        XYLog("%s: unexpected pairwise key update received from ..:%02x:%02x\n",
              ic->ic_if.if_xname, ni->ni_macaddr[4], ni->ni_macaddr[5]);
}

void AirportItlwmSkywalkInterface::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;

    if (gtk != NULL) {
        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (keylen < 0 || key_len != (size_t)keylen) {
            XYLog("GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        /* map GTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        if (k->k_cipher == IEEE80211_CIPHER_NONE || k->k_len != (u_int)keylen || memcmp(k->k_key, gtk, keylen) != 0) {
            memset(k, 0, sizeof(*k));
            k->k_id = kid;    /* 0-3 */
            k->k_cipher = ni->ni_rsngroupcipher;
            k->k_flags = IEEE80211_KEY_GROUP;
            //if (gtk[6] & (1 << 2))
            //  k->k_flags |= IEEE80211_KEY_TX;
            k->k_rsc[0] = LE_READ_6(rsc);
            k->k_len = keylen;
            memcpy(k->k_key, gtk, k->k_len);
            /* install the GTK */
            if ((*ic->ic_set_key)(ic, ni, k) != 0) {
                XYLog("setting GTK failed\n");
                return;
            }
            else
                XYLog("setting GTK successfully\n");
        }
    }

    if (true) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            XYLog("marking port ..:%02x:%02x valid\n", ni->ni_macaddr[4], ni->ni_macaddr[5]);
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINK_STATE_UP);
            ni->ni_assoc_fail = 0;
            if (ic->ic_opmode == IEEE80211_M_STA)
                ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
        }
    }
}

bool AirportItlwmSkywalkInterface::
init(IOService *provider)
{
    bool ret = IO80211InfraInterface::init();
    if (!ret) {
        XYLog("%s IO80211InfraInterface init failed\n", __PRETTY_FUNCTION__);
        return false;
    }
    instance = OSDynamicCast(AirportItlwm, provider);
    if (!instance)
        return false;
    this->fHalService = instance->fHalService;
    this->scanSource = instance->scanSource;
#ifdef AIRPORT_WCL
    IOEthernetAddress address;
    if (instance->getHardwareAddress(&address) != kIOReturnSuccess)
        return false;
    memcpy(wclPermanentMAC, &address, sizeof(wclPermanentMAC));
    if (!IO80211SkywalkInterface::init(provider, reinterpret_cast<ether_addr *>(&address)))
        return false;
    if (!initWCL())
        return false;
#endif
    return ret;
}

IOReturn AirportItlwmSkywalkInterface::
setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data *data)
{
    auto publish = [](AirportItlwm *controller, const char *key, UInt64 value) {
        OSNumber *number = OSNumber::withNumber(value, 64);
        if (number) {
            controller->setProperty(key, number);
            number->release();
        }
    };

    if (!instance)
        return kIOReturnNotReady;

    publish(instance, "ItlwmAWDLCreateRequests", __sync_add_and_fetch(&instance->awdlCreateRequests, 1));
    if (!data) {
        publish(instance, "ItlwmAWDLCreateResult", kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    publish(instance, "ItlwmAWDLCreateRole", data->role);
    if (!instance->awdlInterfaceTest || data->role != APPLE80211_VIF_AWDL) {
        publish(instance, "ItlwmAWDLCreateResult", kIOReturnUnsupported);
        return kIOReturnUnsupported;
    }
    if (instance->fAWDLInterface) {
        publish(instance, "ItlwmAWDLCreateResult", kIOReturnSuccess);
        return kIOReturnSuccess;
    }

    ether_addr address;
    memcpy(address.octet, data->mac, sizeof(address.octet));
    const bool attached = instance->attachVirtualInterface(&instance->fAWDLInterface, &address, data->role, false);
    IOReturn result = attached ? kIOReturnSuccess : kIOReturnError;
#if defined(ITL_AWDL_NATIVE)
    if (attached) {
        result = static_cast<ItlAWDLInterface *>(instance->fAWDLInterface)->initializeNetwork(
            instance, instance->getWorkQueue(), address);
        if (result != kIOReturnSuccess) {
            // initializeNetwork unwinds an unpublished object. Native virtual
            // terminate() assumes a started controller context, which a failed
            // start does not guarantee; detach this unpublished service directly.
            instance->fAWDLInterface->detach(instance);
            instance->fAWDLInterface->release();
            instance->fAWDLInterface = nullptr;
        }
    }
#endif
    publish(instance, "ItlwmAWDLCreateResult", result);
    return result;
}

//ifnet_t AirportItlwmSkywalkInterface::
//getBSDInterface()
//{
//    if (instance->bsdInterface)
//        return instance->bsdInterface->getIfnet();
//    return NULL;
//}

IOReturn AirportItlwmSkywalkInterface::
getSSID(struct apple80211_ssid_data *sd)
{
    if (!sd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
#ifdef AIRPORT_WCL
        sd->ssid_len = MIN(ic->ic_bss->ni_esslen, sizeof(sd->ssid_bytes));
        memcpy(sd->ssid_bytes, ic->ic_bss->ni_essid, sd->ssid_len);
#else
        // ic_des_essid is a 32-byte field with no terminator: a 32-byte SSID made strlen run into the next
        // fields (audit P-S01). Use the stored length, bounded by both buffers.
        sd->ssid_len = (uint32_t)ItlCopy::copyCounted(sd->ssid_bytes, sizeof(sd->ssid_bytes), ic->ic_des_essid,
                                                      sizeof(ic->ic_des_essid), ic->ic_des_esslen);
#endif
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    if (!ad)     // audit P-V03
        return kIOReturnBadArgument;
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    if (!ad)
        return kIOReturnBadArgument;
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setCIPHER_KEY(struct apple80211_key *key)
{
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(8), key);
#else
    // Used on Sonoma, which has no WCL. Never log key material, and check every caller length and
    // index before it is used (security audit L02).
    if (!key)
        return kIOReturnBadArgument;
    if (key->key_len > APPLE80211_KEY_BUFF_LEN || key->key_rsc_len > APPLE80211_RSC_LEN ||
        key->key_index >= IEEE80211_WEP_NKID)
        return kIOReturnBadArgument;
    XYLog("%s: len=%u cipher_type=%u flags=%u index=%u rsc_len=%u\n", __FUNCTION__,
          key->key_len, key->key_cipher_type, key->key_flags, key->key_index, key->key_rsc_len);
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");

    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            // setPTK and setGTK use the current BSS node.
            if (!fHalService->get80211Controller()->ic_bss)
                return kIOReturnNotReady;
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_MSK:
            XYLog("Setting MSK\n");
            if (!fHalService->get80211Controller()->ic_bss || key->key_len < 32)
                return kIOReturnBadArgument;
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA\n");
            if (!fHalService->get80211Controller()->ic_bss || key->key_len < 32)
                return kIOReturnBadArgument;
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getPHY_MODE(struct apple80211_phymode_data *pd)
{
    if (!pd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();

    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;

    if (ic->ic_flags & IEEE80211_F_VHTON)
        pd->phy_mode |= APPLE80211_MODE_11AC;

    if (ic->ic_flags & IEEE80211_F_HEON)
        pd->phy_mode |= APPLE80211_MODE_11AX;

    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
        case IEEE80211_MODE_11AX:
            pd->active_phy_mode = ic->ic_state == IEEE80211_S_RUN && ic->ic_bss &&
                (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) ? APPLE80211_MODE_11AX : APPLE80211_MODE_AUTO;
            break;

        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }

    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNEL(struct apple80211_channel_data *cd)
{
    if (!cd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags, ic->ic_bss->ni_chw);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATE(struct apple80211_state_data *sd)
{
    if (!sd)     // audit P-V03
        return kIOReturnBadArgument;
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    sd->state = fHalService->get80211Controller()->ic_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_INDEX_SET(struct apple80211_mcs_index_set_data *ad)
{
    if (!ad)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (size_t i = 0; i < size; i++)
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        return kIOReturnSuccess;
    }
    return 6;
}

extern bool itlAWDLBuildAllowed();
extern bool itlAWDLFlag(const char *name);
extern int itlAWDLNoteCardStreams(const struct ieee80211com *ic);
// -itlawdlcaps: answer the native stack's HT and VHT capability requests. Without them it
// assumes one HT stream and no VHT, and advertises that to AWDL peers in TLV 7 and leaves out
// TLV 17, so a peer sends to us at 20 MHz on one stream. The values are the AX211's own.
static bool itlAWDLAdvertiseCaps()
{
    static int cached = -1;
    if (cached < 0) {
        cached = itlAWDLBuildAllowed() && itlAWDLFlag("-itlawdlcaps") ? 1 : 0;
    }
    return cached == 1;
}

IOReturn AirportItlwmSkywalkInterface::
getHT_CAPABILITY(struct apple80211_ht_capability *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
    if (!itlAWDLAdvertiseCaps() || !data)
        return kIOReturnUnsupported;
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->hc_id = IEEE80211_ELEMID_HTCAPS;
    data->hc_len = 26;
    // LDPC, 20/40 MHz, SM power save off, short GI at 20 and 40 MHz: 0x006f, as the stack's default.
    data->hc_cap = 0x006f;
    // Maximum A-MPDU 64 KB, minimum spacing 8 us.
    data->hc_param = 0x1b;
    // MCS 0 to 15 (two spatial streams), or 0 to 7 on a card with one (#87).
    data->hc_mcsset[0] = 0xff;
    data->hc_mcsset[1] = itlAWDLNoteCardStreams(fHalService->get80211Controller()) == 1 ? 0x00 : 0xff;
    return kIOReturnSuccess;
}

// -itlawdlcapshtonly: two HT streams, but no VHT, to see what VHT changes on its own.
static bool itlAWDLAdvertiseHtOnly()
{
    static int cached = -1;
    if (cached < 0) {
        int dummy = 0;
        cached = PE_parse_boot_argn("-itlawdlcapshtonly", &dummy, sizeof(dummy)) ? 1 : 0;
    }
    return cached == 1;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_CAPABILITY(struct apple80211_vht_capability *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
    if (!itlAWDLAdvertiseCaps() || itlAWDLAdvertiseHtOnly() || !data)
        return kIOReturnUnsupported;
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    // The stack copies the 14 bytes after the version: a VHT Capabilities element.
    uint8_t *element = reinterpret_cast<uint8_t *>(data) + 4;
    element[0] = 191;   // Element ID.
    element[1] = 12;    // Length.
    // Max MPDU 3895, 80 MHz only, RX LDPC, short GI at 80 MHz, max A-MPDU exponent 7.
    const uint32_t info = 0x00000010U | 0x00000020U | (7U << 23);
    element[2] = uint8_t(info);
    element[3] = uint8_t(info >> 8);
    element[4] = uint8_t(info >> 16);
    element[5] = uint8_t(info >> 24);
    // MCS 0 to 9 on streams 1 and 2 (stream 1 only on a one-stream card, #87), none on the others,
    // for receive and transmit.
    const uint8_t streams = itlAWDLNoteCardStreams(fHalService->get80211Controller()) == 1 ? 0xfe : 0xfa;
    element[6] = streams; element[7] = 0xff;
    element[10] = streams; element[11] = 0xff;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_MCS_INDEX_SET(struct apple80211_vht_mcs_index_set_data *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode != IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_vht_mcs_index_set_data));
    data->version = APPLE80211_VERSION;
    data->mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_VHT(struct apple80211_mcs_vht_data *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode != IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_mcs_vht_data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = (ieee80211_node_supports_vht_sgi80(ic->ic_bss) || ieee80211_node_supports_vht_sgi160(ic->ic_bss)) ? APPLE80211_GI_SHORT : APPLE80211_GI_LONG;
    data->index = ic->ic_bss->ni_txmcs;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_40:
            data->bw = 40;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            data->bw = 80;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            data->bw = 160;
            break;

        default:
            data->bw = 20;
            break;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE_SET(struct apple80211_rate_set_data *ad)
{
    if (!ad)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        ad->num_rates = (uint32_t)size;
        for (size_t i=0; i < size; i++) {
            // A reference in every build: the non-WCL copy dropped the values (audit ST01).
            struct apple80211_rate &apple_rate = ad->rates[i];
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getOP_MODE(struct apple80211_opmode_data *od)
{
    if (!od)     // audit P-V03
        return kIOReturnBadArgument;
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getTXPOWER(struct apple80211_txpower_data *txd)
{
    if (!txd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = ic->ic_txpower;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE(struct apple80211_rate_data *rd)
{
    if (!rd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL)
        return 6;
    int nss;
    int sgi;
    int index = 0;
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        sgi = ieee80211_node_supports_sgi(ic->ic_bss);
        if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
            rd->rate[0] = ic->ic_bss->ni_he_txrate_kbps / 1000;
        } else if (ic->ic_curmode == IEEE80211_MODE_11AC) {
            if (sgi)
                index += 1;
            nss = fHalService->getDriverInfo()->getTxNSS();
            switch (ic->ic_bss->ni_chw) {
                case IEEE80211_CHAN_WIDTH_40:
                    index += 4;
                    break;
                case IEEE80211_CHAN_WIDTH_80:
                    index += 8;
                    break;
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    index += 12;
                    break;

                default:
                    break;
            }
            index += 2 * (nss - 1);
            const struct ieee80211_vht_rateset *rs = &ieee80211_std_ratesets_11ac[index];
            rd->rate[0] = rs->rates[ic->ic_bss->ni_txmcs % rs->nrates] / 2;
        } else if (ic->ic_curmode == IEEE80211_MODE_11N) {
            int is_40mhz = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_40;
            if (sgi)
                index += 1;
            if (is_40mhz)
                index += (IEEE80211_HT_RATESET_MIMO4_SGI + 1);
            index += (ic->ic_bss->ni_txmcs / 16);
            nss = ic->ic_bss->ni_txmcs / 8 + 1;
            index += 2 * (nss - 1);
            rd->rate[0] = ieee80211_std_ratesets_11n[index].rates[ic->ic_bss->ni_txmcs % 8] / 2;
        } else
            rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getBSSID(struct apple80211_bssid_data *bd)
{
    if (!bd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSSI(struct apple80211_rssi_data *rd)
{
    if (!rd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSN_IE(struct apple80211_rsn_ie_data *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(10), data);
#elif defined(USE_APPLE_SUPPLICANT)
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(9), data);
#elif defined(USE_APPLE_SUPPLICANT)
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAP_IE_LIST(struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len == 0 || ic->ic_bss->ni_rsnie_tlv_len > data->len || ic->ic_bss->ni_rsnie_tlv_len > 1024)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNOISE(struct apple80211_noise_data *nd)
{
    if (!nd)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = -fHalService->getDriverInfo()->getBSSNoise();
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getPOWERSAVE(struct apple80211_powersave_data *pd)
{
    if (!pd)     // audit P-V03
        return kIOReturnBadArgument;
    pd->version = APPLE80211_VERSION;
    // The link may only report itself as idle when the framework has not
    // asked for the power saving to be turned off. The level is only kept by
    // the WCL builds, the others have no power saving of their own.
#ifdef AIRPORT_WCL
    pd->powersave_level = (wclPowersaveLevel != APPLE80211_POWERSAVE_MODE_DISABLED)
                               ? APPLE80211_POWERSAVE_MODE_80211
                               : APPLE80211_POWERSAVE_MODE_DISABLED;
#else
    pd->powersave_level = APPLE80211_POWERSAVE_MODE_DISABLED;
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getNSS(struct apple80211_nss_data *data)
{
    if (!data)     // audit P-V03
        return kIOReturnBadArgument;
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setASSOCIATE(struct apple80211_assoc_data *ad)
{
    // Joins normally come through setWCL_ASSOCIATE, whose decoder bounds every length. This legacy
    // entry point used to read and copy caller lengths unchecked; check them before anything else.
    if (!ad)
        return kIOReturnBadArgument;
    if (ad->ad_ssid_len > APPLE80211_MAX_SSID_LEN || ad->ad_key.key_len > APPLE80211_KEY_BUFF_LEN ||
        ad->ad_key.key_index >= IEEE80211_WEP_NKID || size_t(ad->ad_rsn_ie[1]) + 2 > APPLE80211_MAX_RSN_IE_LEN)
        return kIOReturnBadArgument;
    // The SSID's length only, not its name: -itllog publishes this log in the registry (audit HL02).
    XYLog("%s ssid_len=%d mode=%d ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%d%s%s%s%s%s%s%s\n", __FUNCTION__, int(ad->ad_ssid_len), ad->ad_mode, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_rsn_ie_len,
          (ad->ad_flags & 2) ? ", Instant Hotspot" : "",
          (ad->ad_flags & 4) ? ", Auto Instant Hotspot" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 1) ? ", don't disassociate" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 2) ? ", don't blacklist" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 4) ? ", closed Network" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 8) ? ", 802.1X" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 0x20) ? ", force BSSID" : "");

    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic)
        return kIOReturnNotReady;

    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;

    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;

    if (ad->ad_mode != APPLE80211_AP_MODE_IBSS) {
        // Refuse before the auth type and RSN element are changed, so a refused join leaves the
        // current settings as they were and macOS sees the error (audit F01).
        if (!associateRequestValid(ad->ad_ssid, ad->ad_ssid_len, ad->ad_auth_lower, ad->ad_auth_upper,
                                   ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index))
            return kIOReturnBadArgument;
        disassocIsVoluntary = false;
        auth_type_data.version = APPLE80211_VERSION;
        auth_type_data.authtype_upper = ad->ad_auth_upper;
        auth_type_data.authtype_lower = ad->ad_auth_lower;
        setAUTH_TYPE(&auth_type_data);
        rsn_ie_data.version = APPLE80211_VERSION;
        rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
        memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
        setRSN_IE(&rsn_ie_data);

        return associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDISASSOCIATE(struct apple80211_disassoc_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;

    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);

    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;

    disassocIsVoluntary = true;

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
#ifdef USE_APPLE_SUPPLICANT
    ic->ic_rsn_ie_override[1] = 0;
#endif
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnError;
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 0;
    struct ieee80211com *ic = fHalService->get80211Controller();
    // Never past the reply's array (audit P-V03).
    for (int i = 0; i < IEEE80211_CHAN_MAX && ad->num_channels < APPLE80211_MAX_CHANNELS; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            ad->supported_channels[ad->num_channels].channel = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags = ieeeChanFlag2appleScanFlagVentura(ic->ic_channels[i].ic_flags);
            ad->num_channels++;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLOCALE(struct apple80211_locale_data *ld)
{
    if (!ld)
        return kIOReturnError;
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;

    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDEAUTH(struct apple80211_deauth_data *da)
{
    if (!da)
        return kIOReturnError;
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getASSOCIATION_STATUS(struct apple80211_assoc_status_data *hv)
{
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (!hv)
        return kIOReturnError;
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN)
        hv->status = APPLE80211_STATUS_SUCCESS;
    else
        hv->status = APPLE80211_STATUS_UNAVAILABLE;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCANCACHE_CLEAR(void *req)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN))
        return kIOReturnSuccess;
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDEAUTH(struct apple80211_deauth_data *da)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS(struct apple80211_mcs_data* md)
{
    if (!md)     // audit P-V03
        return kIOReturnBadArgument;
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL || !md)
        return 6;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLINK_CHANGED_EVENT_DATA(struct apple80211_link_changed_event_data *ed)
{
    if (ed == nullptr)
        return 16;

    struct ieee80211com *ic = fHalService->get80211Controller();

    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(instance->currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        ed->voluntary = disassocIsVoluntary;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
    } else if (ic->ic_bss)      // audit P-V03
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    XYLog("Link %s, reason: %d, voluntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->voluntary);
    return kIOReturnSuccess;
}

// Scan diagnostic for the station scan path (#20, #24, #45: scans end with no results). 0.6.0-alpha.1 put
// these counters in AirportSTAIOCTL.cpp, which no target builds (audit T03), so the Sonoma kext had none.
// Requests, refusals ("wrap": the last result list is still being read; "init": the interface isn't up),
// and results per list. The Sonoma kext (no WCL) publishes them as ItlwmScanStats, the key testers are
// asked for; the WCL kexts already use that key for the WCL path, so there they are ItlwmScanStatsSTA.
static uint32_t staScanRequests, staScanWrap, staScanInit, staScanAccepted, staScanLists, staScanEmptyLists,
    staScanResults, staScanLastCount, staScanCount;

static void staScanPublish(IOService *service)
{
    if (!service)
        return;
    char text[160];
    snprintf(text, sizeof(text), "req=%u ok=%u wrap=%u init=%u lists=%u empty=%u results=%u last=%u",
             staScanRequests, staScanAccepted, staScanWrap, staScanInit, staScanLists, staScanEmptyLists,
             staScanResults, staScanLastCount);
#ifdef AIRPORT_WCL
    service->setProperty("ItlwmScanStatsSTA", text);
#else
    service->setProperty("ItlwmScanStats", text);
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setSCAN_REQ(struct apple80211_scan_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
#if 0
    XYLog("%s Type: %u BSS Type: %u PHY Mode: %u Dwell time: %u Rest time: %u Num channels: %u SSID: %s BSSID: %s\n",
          __FUNCTION__,
          sd->scan_type,
          sd->bss_type,
          sd->phy_mode,
          sd->dwell_time,
          sd->rest_time,
          sd->num_channels,
          sd->ssid,
          ether_sprintf(sd->bssid.octet));
#endif
    if (!sd)
        return kIOReturnBadArgument;
    if (!ic)
        return kIOReturnNotReady;
    ++staScanRequests;
    if (fScanCursor.wrapping) {
        ++staScanWrap;
        staScanPublish(instance);
        return 22;
    }
    if (ic->ic_state <= IEEE80211_S_INIT) {
        ++staScanInit;
        staScanPublish(instance);
        return 22;
    }
    ++staScanAccepted;
    staScanPublish(instance);
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST || sd->scan_type == APPLE80211_SCAN_TYPE_PASSIVE) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

extern OSDictionary *convertScanToDictionary(apple80211_scan_result *a1);

static int convertNodeToScanResult(ItlHalService *fHalService, struct ieee80211_node *fNextNodeToSend, apple80211_scan_result *result)
{
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv && fNextNodeToSend->ni_rsnie_tlv_len > 0) {
        size_t ielen = MIN((size_t)fNextNodeToSend->ni_rsnie_tlv_len, sizeof(result->asr_ie_data));
        result->asr_ie_len = (int16_t)ielen;
        memcpy(result->asr_ie_data, fNextNodeToSend->ni_rsnie_tlv, ielen);
    } else {
        result->asr_ie_len = 0;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
    // The count first, bounded by both arrays; the loop ran zero times before (audit ST06).
    result->asr_nrates = (uint8_t)ItlCopy::copyCounted(result->asr_rates, APPLE80211_MAX_RATES,
                                                       fNextNodeToSend->ni_rates.rs_rates, IEEE80211_RATE_MAXSIZE,
                                                       fNextNodeToSend->ni_rates.rs_nrates);
    result->asr_age = (uint32_t)(airport_up_time() - fNextNodeToSend->ni_age_ts);
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2appleScanFlagVentura(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = -fHalService->getDriverInfo()->getBSSNoise();
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0)
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len);
    return 0;
}

IOReturn AirportItlwmSkywalkInterface::
getCURRENT_NETWORK(apple80211_scan_result *sr)
{
    if (!sr)     // audit P-V03
        return kIOReturnBadArgument;
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || fHalService->get80211Controller()->ic_bss == NULL)
        return kIOReturnError;
    convertNodeToScanResult(fHalService, fHalService->get80211Controller()->ic_bss, sr);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *as)
{
    if (!as)
        return kIOReturnBadArgument;
    as->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSCAN_RESULT(struct apple80211_scan_result *sr)
{
    if (!sr)
        return kIOReturnBadArgument;
    // The node tree can change between two requests (cache expiry, scan end, state changes free nodes), so
    // no node pointer is kept across them (audit ST02). include/ItlScanCursor.hpp, tests/scan_cursor.cpp.
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic)
        return kIOReturnNotReady;
    const bool newList = !fScanCursor.started && !fScanCursor.wrapping;
    struct ieee80211_node *node = ItlScan::nextResult<struct ieee80211_node>(fScanCursor,
        [ic]() { return RB_MIN(ieee80211_tree, &ic->ic_tree); },
        [](struct ieee80211_node *n) { return RB_NEXT(ieee80211_tree, unused, n); },   // RB_NEXT needs no tree
        [](struct ieee80211_node *n) -> const uint8_t * { return n->ni_macaddr; });
    if (node == NULL) {
        ++staScanLists;
        if (newList) {
            ++staScanEmptyLists;
            staScanLastCount = staScanCount = 0;
        } else {
            staScanLastCount = staScanCount;
            staScanCount = 0;
        }
        staScanPublish(instance);
        return 5;
    }
    ++staScanCount;
    ++staScanResults;
    convertNodeToScanResult(fHalService, node, sr);
    ItlScan::noteReturned(fScanCursor, node->ni_macaddr, RB_NEXT(ieee80211_tree, &ic->ic_tree, node) == NULL);

    return kIOReturnSuccess;
}

#ifdef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getHW_ADDR(apple80211_hw_mac_address *data)
{
    if (!data) return kIOReturnBadArgument;
    AirportWCL::HardwareAddress value;
    if (!AirportWCL::copyHardwareAddress(wclPermanentMAC, value)) return kIOReturnNotReady;
    memcpy(data, &value, sizeof(value));
    return kIOReturnSuccess;
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportItlwmSkywalkInterface::setMacAddress(ether_addr &address)
{
    return instance->setHardwareAddress(&address, IEEE80211_ADDR_LEN);
}
#else
IOReturn AirportItlwmSkywalkInterface::setMacAddress(mloAddrArray &addresses)
{
    return instance->setHardwareAddress(&addresses, IEEE80211_ADDR_LEN);
}
#endif

#endif

#ifndef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getHW_ADDR(apple80211_hw_mac_address *)
{
    return kIOReturnUnsupported;
}
#endif

#ifndef AIRPORT_WCL
// Sonoma has no WCL, but the same metric matters: without it en0's link quality stays "off" (-2),
// apsd won't connect push over Wi-Fi, and iMessage fails (upstream's Sonoma release notes say as
// much). IOSkywalkNetworkInterface::reportLinkQuality is exported by 23J631's IOSkywalkFamily.
extern "C" IOReturn itlReportLinkQualitySonoma(IOSkywalkNetworkInterface *, unsigned int)
    __asm__("__ZN25IOSkywalkNetworkInterface17reportLinkQualityEj");

void AirportItlwmSkywalkInterface::postLinkQuality()
{
    struct ieee80211com *ic = fHalService ? fHalService->get80211Controller() : nullptr;
    if (!ic)
        return;
    // The kernel's IFNET_LQM_THRESH_* values: off -2, bad 10, poor 50, good 100.
    const bool up = ic->ic_state == IEEE80211_S_RUN && ic->ic_bss && ic->ic_bss->ni_port_valid;
    int32_t quality = -2;
    if (up) {
        if (++linkQualityTicks % 2)
            return;
        apple80211_rssi_data rssi = {};
        if (getRSSI(&rssi) != kIOReturnSuccess || rssi.aggregate_rssi >= 0)
            return;
        quality = rssi.aggregate_rssi >= -70 ? 100 : rssi.aggregate_rssi >= -80 ? 50 : 10;
        if (quality == linkQualityReported)
            return;
    } else if (!linkQualityReported) {
        return;   // already off, or never reported
    }
    const IOReturn result = itlReportLinkQualitySonoma(static_cast<IOSkywalkNetworkInterface *>(this), uint32_t(quality));
    if (result == kIOReturnSuccess)
        linkQualityReported = up ? quality : 0;
    setProperty("ItlwmLinkQuality", uint64_t(uint32_t(quality)), 32);
    setProperty("ItlwmLinkQualityResult", uint64_t(uint32_t(result)), 32);
}
#endif
