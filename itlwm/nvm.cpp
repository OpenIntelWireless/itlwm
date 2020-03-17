//
//  nvm.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef CUSTOM_HEADER
#include "itlwm.hpp"
#else
#include "OpenWifi.hpp"
#endif

/*
 * NVM read access and content parsing.  We do not support
 * external NVM or writing NVM.
 */

/* list of NVM sections we are allowed/need to read */
const int iwm_nvm_to_read[] = {
    IWM_NVM_SECTION_TYPE_HW,
    IWM_NVM_SECTION_TYPE_SW,
    IWM_NVM_SECTION_TYPE_REGULATORY,
    IWM_NVM_SECTION_TYPE_CALIBRATION,
    IWM_NVM_SECTION_TYPE_PRODUCTION,
    IWM_NVM_SECTION_TYPE_REGULATORY_SDP,
    IWM_NVM_SECTION_TYPE_HW_8000,
    IWM_NVM_SECTION_TYPE_MAC_OVERRIDE,
    IWM_NVM_SECTION_TYPE_PHY_SKU,
};

#define IWM_NVM_DEFAULT_CHUNK_SIZE    (2*1024)

#define IWM_NVM_WRITE_OPCODE 1
#define IWM_NVM_READ_OPCODE 0

int itlwm::
iwm_nvm_read_chunk(struct iwm_softc *sc, uint16_t section, uint16_t offset,
    uint16_t length, uint8_t *data, uint16_t *len)
{
    offset = 0;
        struct iwm_nvm_access_cmd nvm_access_cmd = {
            .offset = htole16(offset),
            .length = htole16(length),
            .type = htole16(section),
            .op_code = IWM_NVM_READ_OPCODE,
        };
        struct iwm_nvm_access_resp *nvm_resp;
        struct iwm_rx_packet *pkt;
        struct iwm_host_cmd cmd = {
            .id = IWM_NVM_ACCESS_CMD,
            .flags = (IWM_CMD_WANT_RESP | IWM_CMD_SEND_IN_RFKILL),
            .resp_pkt_len = IWM_CMD_RESP_MAX,
            .data = { &nvm_access_cmd, },
        };
        int err, offset_read;
        size_t bytes_read;
        uint8_t *resp_data;
    
        cmd.len[0] = sizeof(struct iwm_nvm_access_cmd);
    
        err = iwm_send_cmd(sc, &cmd);
        if (err)
            return err;
    
        pkt = cmd.resp_pkt;
        if (pkt->hdr.flags & IWM_CMD_FAILED_MSK) {
            err = EIO;
            goto exit;
        }
    
        /* Extract NVM response */
        nvm_resp = (struct iwm_nvm_access_resp *)pkt->data;
        if (nvm_resp == NULL)
            return EIO;
    
        err = le16toh(nvm_resp->status);
        bytes_read = le16toh(nvm_resp->length);
        offset_read = le16toh(nvm_resp->offset);
        resp_data = nvm_resp->data;
        if (err) {
            err = EINVAL;
            goto exit;
        }
    
        if (offset_read != offset) {
            err = EINVAL;
            goto exit;
        }
    
        if (bytes_read > length) {
            err = EINVAL;
            goto exit;
        }
    
        memcpy(data + offset, resp_data, bytes_read);
        *len = bytes_read;
    
     exit:
        iwm_free_resp(sc, &cmd);
        return err;
}

/*
 * Reads an NVM section completely.
 * NICs prior to 7000 family doesn't have a real NVM, but just read
 * section 0 which is the EEPROM. Because the EEPROM reading is unlimited
 * by uCode, we need to manually check in this case that we don't
 * overflow and try to read more than the EEPROM size.
 */
int itlwm::
iwm_nvm_read_section(struct iwm_softc *sc, uint16_t section, uint8_t *data,
    uint16_t *len, size_t max_len)
{
    uint16_t chunklen, seglen;
        int err = 0;
    
        chunklen = seglen = IWM_NVM_DEFAULT_CHUNK_SIZE;
        *len = 0;
    
        /* Read NVM chunks until exhausted (reading less than requested) */
        while (seglen == chunklen && *len < max_len) {
            err = iwm_nvm_read_chunk(sc,
                section, *len, chunklen, data, &seglen);
            if (err)
                return err;
    
            *len += seglen;
        }
    
        return err;
}

int itlwm::
iwm_parse_nvm_data(struct iwm_softc *sc, const uint16_t *nvm_hw,
const uint16_t *nvm_sw, const uint16_t *nvm_calib,
const uint16_t *mac_override, const uint16_t *phy_sku,
const uint16_t *regulatory, int n_regulatory)
{
    struct iwm_nvm_data *data = &sc->sc_nvm;
    uint8_t hw_addr[ETHER_ADDR_LEN];
    uint32_t sku;
    uint16_t lar_config;

    data->nvm_version = le16_to_cpup(nvm_sw + IWM_NVM_VERSION);

    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
            uint16_t radio_cfg = le16_to_cpup(nvm_sw + IWM_RADIO_CFG);
            data->radio_cfg_type = IWM_NVM_RF_CFG_TYPE_MSK(radio_cfg);
            data->radio_cfg_step = IWM_NVM_RF_CFG_STEP_MSK(radio_cfg);
            data->radio_cfg_dash = IWM_NVM_RF_CFG_DASH_MSK(radio_cfg);
            data->radio_cfg_pnum = IWM_NVM_RF_CFG_PNUM_MSK(radio_cfg);
    
            sku = le16_to_cpup(nvm_sw + IWM_SKU);
        } else {
            uint32_t radio_cfg =
                le32_to_cpup((uint32_t *)(phy_sku + IWM_RADIO_CFG_8000));
            data->radio_cfg_type = IWM_NVM_RF_CFG_TYPE_MSK_8000(radio_cfg);
            data->radio_cfg_step = IWM_NVM_RF_CFG_STEP_MSK_8000(radio_cfg);
            data->radio_cfg_dash = IWM_NVM_RF_CFG_DASH_MSK_8000(radio_cfg);
            data->radio_cfg_pnum = IWM_NVM_RF_CFG_PNUM_MSK_8000(radio_cfg);
            data->valid_tx_ant = IWM_NVM_RF_CFG_TX_ANT_MSK_8000(radio_cfg);
            data->valid_rx_ant = IWM_NVM_RF_CFG_RX_ANT_MSK_8000(radio_cfg);
    
            sku = le32_to_cpup((uint32_t *)(phy_sku + IWM_SKU_8000));
        }
    
        data->sku_cap_band_24GHz_enable = sku & IWM_NVM_SKU_CAP_BAND_24GHZ;
        data->sku_cap_band_52GHz_enable = sku & IWM_NVM_SKU_CAP_BAND_52GHZ;
        data->sku_cap_11n_enable = sku & IWM_NVM_SKU_CAP_11N_ENABLE;
        data->sku_cap_mimo_disable = sku & IWM_NVM_SKU_CAP_MIMO_DISABLE;
    
        if (sc->sc_device_family >= IWM_DEVICE_FAMILY_8000) {
            uint16_t lar_offset = data->nvm_version < 0xE39 ?
                           IWM_NVM_LAR_OFFSET_8000_OLD :
                           IWM_NVM_LAR_OFFSET_8000;
    
            lar_config = le16_to_cpup(regulatory + lar_offset);
            data->lar_enabled = !!(lar_config &
                           IWM_NVM_LAR_ENABLED_8000);
            data->n_hw_addrs = le16_to_cpup(nvm_sw + IWM_N_HW_ADDRS_8000);
        } else
            data->n_hw_addrs = le16_to_cpup(nvm_sw + IWM_N_HW_ADDRS);
    
    
        /* The byte order is little endian 16 bit, meaning 214365 */
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
            memcpy(hw_addr, nvm_hw + IWM_HW_ADDR, ETHER_ADDR_LEN);
            data->hw_addr[0] = hw_addr[1];
            data->hw_addr[1] = hw_addr[0];
            data->hw_addr[2] = hw_addr[3];
            data->hw_addr[3] = hw_addr[2];
            data->hw_addr[4] = hw_addr[5];
            data->hw_addr[5] = hw_addr[4];
        } else
            iwm_set_hw_address_8000(sc, data, mac_override, nvm_hw);
    
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
            if (sc->nvm_type == IWM_NVM_SDP) {
                iwm_init_channel_map(sc, regulatory, iwm_nvm_channels,
                    MIN(n_regulatory, nitems(iwm_nvm_channels)));
            } else {
                iwm_init_channel_map(sc, &nvm_sw[IWM_NVM_CHANNELS],
                    iwm_nvm_channels, nitems(iwm_nvm_channels));
            }
        } else
            iwm_init_channel_map(sc, &regulatory[IWM_NVM_CHANNELS_8000],
                iwm_nvm_channels_8000,
                MIN(n_regulatory, nitems(iwm_nvm_channels_8000)));
    
        data->calib_version = 255;   /* TODO:
                        this value will prevent some checks from
                        failing, we need to check if this
                        field is still needed, and if it does,
                        where is it in the NVM */
    
        return 0;
}

int itlwm::
iwm_parse_nvm_sections(struct iwm_softc *sc, struct iwm_nvm_section *sections)
{
    const uint16_t *hw, *sw, *calib, *mac_override = NULL, *phy_sku = NULL;
    const uint16_t *regulatory = NULL;
    int n_regulatory = 0;

    /* Checking for required sections */
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
            if (!sections[IWM_NVM_SECTION_TYPE_SW].data ||
                !sections[IWM_NVM_SECTION_TYPE_HW].data) {
                return ENOENT;
            }
    
            hw = (const uint16_t *) sections[IWM_NVM_SECTION_TYPE_HW].data;
    
            if (sc->nvm_type == IWM_NVM_SDP) {
                if (!sections[IWM_NVM_SECTION_TYPE_REGULATORY_SDP].data)
                    return ENOENT;
                regulatory = (const uint16_t *)
                    sections[IWM_NVM_SECTION_TYPE_REGULATORY_SDP].data;
                n_regulatory =
                    sections[IWM_NVM_SECTION_TYPE_REGULATORY_SDP].length;
            }
        } else if (sc->sc_device_family >= IWM_DEVICE_FAMILY_8000) {
            /* SW and REGULATORY sections are mandatory */
            if (!sections[IWM_NVM_SECTION_TYPE_SW].data ||
                !sections[IWM_NVM_SECTION_TYPE_REGULATORY].data) {
                return ENOENT;
            }
            /* MAC_OVERRIDE or at least HW section must exist */
            if (!sections[IWM_NVM_SECTION_TYPE_HW_8000].data &&
                !sections[IWM_NVM_SECTION_TYPE_MAC_OVERRIDE].data) {
                return ENOENT;
            }
    
            /* PHY_SKU section is mandatory in B0 */
            if (!sections[IWM_NVM_SECTION_TYPE_PHY_SKU].data) {
                return ENOENT;
            }
    
            regulatory = (const uint16_t *)
                sections[IWM_NVM_SECTION_TYPE_REGULATORY].data;
            n_regulatory = sections[IWM_NVM_SECTION_TYPE_REGULATORY].length;
            hw = (const uint16_t *)
                sections[IWM_NVM_SECTION_TYPE_HW_8000].data;
            mac_override =
                (const uint16_t *)
                sections[IWM_NVM_SECTION_TYPE_MAC_OVERRIDE].data;
            phy_sku = (const uint16_t *)
                sections[IWM_NVM_SECTION_TYPE_PHY_SKU].data;
        } else {
            panic("unknown device family %d\n", sc->sc_device_family);
        }
    
        sw = (const uint16_t *)sections[IWM_NVM_SECTION_TYPE_SW].data;
        calib = (const uint16_t *)
            sections[IWM_NVM_SECTION_TYPE_CALIBRATION].data;
    
        /* XXX should pass in the length of every section */
        return iwm_parse_nvm_data(sc, hw, sw, calib, mac_override,
            phy_sku, regulatory, n_regulatory);
}

int itlwm::
iwm_nvm_init(struct iwm_softc *sc)
{
    struct iwm_nvm_section nvm_sections[IWM_NVM_NUM_OF_SECTIONS];
    int i, section, err = 0;
    uint16_t len;
    uint8_t *buf;
    const size_t bufsz = sc->sc_nvm_max_section_size;

    memset(nvm_sections, 0, sizeof(nvm_sections));

    buf = (uint8_t*)malloc(bufsz, M_DEVBUF, M_WAIT);
    if (buf == NULL)
        return ENOMEM;

    for (i = 0; i < nitems(iwm_nvm_to_read); i++) {
        section = iwm_nvm_to_read[i];
        _KASSERT(section <= nitems(nvm_sections));

        err = iwm_nvm_read_section(sc, section, buf, &len, bufsz);
        if (err) {
            err = 0;
            continue;
        }
        nvm_sections[section].data = (uint8_t*)malloc(len, M_DEVBUF, M_WAIT);
        if (nvm_sections[section].data == NULL) {
            err = ENOMEM;
            break;
        }
        memcpy(nvm_sections[section].data, buf, len);
        nvm_sections[section].length = len;
    }
    free(buf);
    if (err == 0)
        err = iwm_parse_nvm_sections(sc, nvm_sections);

    for (i = 0; i < IWM_NVM_NUM_OF_SECTIONS; i++) {
        if (nvm_sections[i].data != NULL)
            free(nvm_sections[i].data);
    }

    return err;
}
