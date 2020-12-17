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
/*    $OpenBSD: if_iwm.c,v 1.316 2020/12/07 20:09:24 tobhe Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ItlIwm.hpp"

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

int ItlIwm::
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
int ItlIwm::
iwm_nvm_read_section(struct iwm_softc *sc, uint16_t section, uint8_t *data,
                     uint16_t *len, size_t max_len)
{
    XYLog("%s\n", __FUNCTION__);
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

int ItlIwm::
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

int ItlIwm::
iwm_parse_nvm_sections(struct iwm_softc *sc, struct iwm_nvm_section *sections)
{
    XYLog("%s\n", __FUNCTION__);
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

int ItlIwm::
iwm_nvm_init(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
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
    ::free(buf);
    if (err == 0)
        err = iwm_parse_nvm_sections(sc, nvm_sections);
    
    for (i = 0; i < IWM_NVM_NUM_OF_SECTIONS; i++) {
        if (nvm_sections[i].data != NULL)
            ::free(nvm_sections[i].data);
    }
    
    return err;
}
