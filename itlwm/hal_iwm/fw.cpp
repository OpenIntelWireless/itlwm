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
#include "rs.h"
#include <FwData.h>

uint8_t ItlIwm::
iwm_lookup_cmd_ver(struct iwm_softc *sc, uint8_t grp, uint8_t cmd)
{
   const struct iwm_fw_cmd_version *entry;
   int i;

   for (i = 0; i < sc->n_cmd_versions; i++) {
       entry = &sc->cmd_versions[i];
       if (entry->group == grp && entry->cmd == cmd)
           return entry->cmd_ver;
   }

   return IWM_FW_CMD_VER_UNKNOWN;
}

int ItlIwm::
iwm_store_cscheme(struct iwm_softc *sc, uint8_t *data, size_t dlen)
{
    struct iwm_fw_cscheme_list *l = (struct iwm_fw_cscheme_list *)data;
    
    if (dlen < sizeof(*l) ||
        dlen < sizeof(l->size) + l->size * sizeof(*l->cs))
        return EINVAL;
    
    /* we don't actually store anything for now, always use s/w crypto */
    
    return 0;
}

int ItlIwm::
iwm_firmware_store_section(struct iwm_softc *sc, enum iwm_ucode_type type,
                           uint8_t *data, size_t dlen)
{
    struct iwm_fw_sects *fws;
    struct iwm_fw_onesect *fwone;
    
    if (type >= IWM_UCODE_TYPE_MAX)
        return EINVAL;
    if (dlen < sizeof(uint32_t))
        return EINVAL;
    
    fws = (struct iwm_fw_sects*)&sc->sc_fw.fw_sects[type];
    if (fws->fw_count >= IWM_UCODE_SECT_MAX)
        return EINVAL;
    
    fwone = (struct iwm_fw_onesect*)&fws->fw_sect[fws->fw_count];
    
    /* first 32bit are device load offset */
    memcpy(&fwone->fws_devoff, data, sizeof(uint32_t));
    
    /* rest is data */
    fwone->fws_data = data + sizeof(uint32_t);
    fwone->fws_len = dlen - sizeof(uint32_t);
    
    fws->fw_count++;
    fws->fw_totlen += fwone->fws_len;
    
    return 0;
}

#define IWM_DEFAULT_SCAN_CHANNELS 40
/* Newer firmware might support more channels. Raise this value if needed. */
#define IWM_MAX_SCAN_CHANNELS        52 /* as of 8265-34 firmware image */

struct iwm_tlv_calib_data {
    uint32_t ucode_type;
    struct iwm_tlv_calib_ctrl calib;
} __packed;

int ItlIwm::
iwm_set_default_calib(struct iwm_softc *sc, const void *data)
{
    const struct iwm_tlv_calib_data *def_calib = (const struct iwm_tlv_calib_data *)data;
    uint32_t ucode_type = le32toh(def_calib->ucode_type);
    
    if (ucode_type >= IWM_UCODE_TYPE_MAX)
        return EINVAL;
    
    sc->sc_default_calib[ucode_type].flow_trigger =
    def_calib->calib.flow_trigger;
    sc->sc_default_calib[ucode_type].event_trigger =
    def_calib->calib.event_trigger;
    
    return 0;
}

void ItlIwm::
iwm_fw_info_free(struct iwm_fw_info *fw)
{
    ::free(fw->fw_rawdata);
    fw->fw_rawdata = NULL;
    fw->fw_rawsize = 0;
    /* don't touch fw->fw_status */
    memset(fw->fw_sects, 0, sizeof(fw->fw_sects));
}

void
iwm_fw_version_str(char *buf, size_t bufsize,
    uint32_t major, uint32_t minor, uint32_t api)
{
    /*
     * Starting with major version 35 the Linux driver prints the minor
     * version in hexadecimal.
     */
    if (major >= 35)
        snprintf(buf, bufsize, "%u.%08x.%u", major, minor, api);
    else
        snprintf(buf, bufsize, "%u.%u.%u", major, minor, api);
}

int ItlIwm::
iwm_read_firmware(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    struct iwm_fw_info *fw = &sc->sc_fw;
    struct iwm_tlv_ucode_header *uhdr;
    struct iwm_ucode_tlv tlv;
    uint32_t usniffer_img;
    uint32_t paging_mem_size;
    uint32_t tlv_type;
    uint8_t *data;
    int err = 0;
    size_t len;
    OSData *fwData = NULL;
    
    if (fw->fw_status == IWM_FW_STATUS_DONE &&
        ucode_type != IWM_UCODE_TYPE_INIT)
        return 0;
    
    while (fw->fw_status == IWM_FW_STATUS_INPROGRESS)
        tsleep_nsec(&sc->sc_fw, 0, "iwmfwp", INFSLP);
    fw->fw_status = IWM_FW_STATUS_INPROGRESS;
    
    if (fw->fw_rawdata != NULL)
        iwm_fw_info_free(fw);
    
    //TODO
    //    err = loadfirmware(sc->sc_fwname,
    //        (u_char **)&fw->fw_rawdata, &fw->fw_rawsize);
//    IOLockLock(fwLoadLock);
//    ResourceCallbackContext context =
//    {
//        .context = this,
//        .resource = NULL
//    };
//
//    //here leaks
//    IOReturn ret = OSKextRequestResource(OSKextGetCurrentIdentifier(), sc->sc_fwname, onLoadFW, &context, NULL);
//    IOLockSleep(fwLoadLock, this, 0);
//    IOLockUnlock(fwLoadLock);
//    if (context.resource == NULL) {
//        XYLog("%s resource load fail.\n", sc->sc_fwname);
//        goto out;
//    }
//    fw->fw_rawdata = malloc(context.resource->getLength(), 1, 1);
//    memcpy(fw->fw_rawdata, context.resource->getBytesNoCopy(), context.resource->getLength());
//    fw->fw_rawsize = context.resource->getLength();
    fwData = getFWDescByName(sc->sc_fwname);
    if (fwData == NULL) {
        XYLog("%s resource load fail.\n", sc->sc_fwname);
        err = EINVAL;
        goto out;
    }
    fw->fw_rawsize = fwData->getLength() * 4;
    fw->fw_rawdata = malloc(fw->fw_rawsize, 1, 1);
    uncompressFirmware((u_char *)fw->fw_rawdata, (uint *)&fw->fw_rawsize, (u_char *)fwData->getBytesNoCopy(), fwData->getLength());
    XYLog("load firmware %s done\n", sc->sc_fwname);
    sc->sc_capaflags = 0;
    sc->sc_capa_n_scan_channels = IWM_DEFAULT_SCAN_CHANNELS;
    memset(sc->sc_enabled_capa, 0, sizeof(sc->sc_enabled_capa));
    sc->n_cmd_versions = 0;
    memset(sc->sc_ucode_api, 0, sizeof(sc->sc_ucode_api));
    memcpy(sc->sc_fw_mcc, "ZZ", sizeof(sc->sc_fw_mcc));
    sc->sc_fw_mcc_int = 0x3030;
    
    uhdr = (struct iwm_tlv_ucode_header *)fw->fw_rawdata;
    if (*(uint32_t *)fw->fw_rawdata != 0
        || le32toh(uhdr->magic) != IWM_TLV_UCODE_MAGIC) {
        XYLog("%s: invalid firmware %s\n",
              DEVNAME(sc), sc->sc_fwname);
        err = EINVAL;
        goto out;
    }
    
    iwm_fw_version_str(sc->sc_fwver, sizeof(sc->sc_fwver),
                       IWM_UCODE_MAJOR(le32toh(uhdr->ver)),
                       IWM_UCODE_MINOR(le32toh(uhdr->ver)),
                       IWM_UCODE_API(le32toh(uhdr->ver)));
    
    data = uhdr->data;
    len = fw->fw_rawsize - sizeof(*uhdr);
    
    while (len >= sizeof(tlv)) {
        size_t tlv_len;
        void *tlv_data;
        
        memcpy(&tlv, data, sizeof(tlv));
        tlv_len = le32toh(tlv.length);
        tlv_type = le32toh(tlv.type);
        
        len -= sizeof(tlv);
        data += sizeof(tlv);
        tlv_data = data;
        
        if (len < tlv_len) {
            XYLog("%s: firmware too short: %zu bytes\n",
                  DEVNAME(sc), len);
            err = EINVAL;
            goto parse_out;
        }
        
        switch (tlv_type) {
            case IWM_UCODE_TLV_PROBE_MAX_LEN:
                if (tlv_len < sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_max_probe_len
                = le32toh(*(uint32_t *)tlv_data);
                if (sc->sc_capa_max_probe_len >
                    IWM_SCAN_OFFLOAD_PROBE_REQ_SIZE) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            case IWM_UCODE_TLV_PAN:
                if (tlv_len) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capaflags |= IWM_UCODE_TLV_FLAGS_PAN;
                break;
            case IWM_UCODE_TLV_FLAGS:
                if (tlv_len < sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                /*
                 * Apparently there can be many flags, but Linux driver
                 * parses only the first one, and so do we.
                 *
                 * XXX: why does this override IWM_UCODE_TLV_PAN?
                 * Intentional or a bug?  Observations from
                 * current firmware file:
                 *  1) TLV_PAN is parsed first
                 *  2) TLV_FLAGS contains TLV_FLAGS_PAN
                 * ==> this resets TLV_PAN to itself... hnnnk
                 */
                sc->sc_capaflags = le32toh(*(uint32_t *)tlv_data);
                break;
            case IWM_UCODE_TLV_CSCHEME:
                err = iwm_store_cscheme(sc, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_NUM_OF_CPU: {
                uint32_t num_cpu;
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                num_cpu = le32toh(*(uint32_t *)tlv_data);
                if (num_cpu < 1 || num_cpu > 2) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            }
            case IWM_UCODE_TLV_SEC_RT:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_TYPE_REGULAR, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_SEC_INIT:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_TYPE_INIT, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_SEC_WOWLAN:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_TYPE_WOW, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_DEF_CALIB:
                if (tlv_len != sizeof(struct iwm_tlv_calib_data)) {
                    err = EINVAL;
                    goto parse_out;
                }
                err = iwm_set_default_calib(sc, tlv_data);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_PHY_SKU:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_fw_phy_config = le32toh(*(uint32_t *)tlv_data);
                break;
                
            case IWM_UCODE_TLV_API_CHANGES_SET: {
                struct iwm_ucode_api *api;
                int idx, i;
                if (tlv_len != sizeof(*api)) {
                    err = EINVAL;
                    goto parse_out;
                }
                api = (struct iwm_ucode_api *)tlv_data;
                idx = le32toh(api->api_index);
                if (idx >= howmany(IWM_NUM_UCODE_TLV_API, 32)) {
                    err = EINVAL;
                    goto parse_out;
                }
                for (i = 0; i < 32; i++) {
                    if ((le32toh(api->api_flags) & (1 << i)) == 0)
                        continue;
                    setbit(sc->sc_ucode_api, i + (32 * idx));
                }
                break;
            }
                
            case IWM_UCODE_TLV_ENABLED_CAPABILITIES: {
                struct iwm_ucode_capa *capa;
                int idx, i;
                if (tlv_len != sizeof(*capa)) {
                    err = EINVAL;
                    goto parse_out;
                }
                capa = (struct iwm_ucode_capa *)tlv_data;
                idx = le32toh(capa->api_index);
                if (idx >= howmany(IWM_NUM_UCODE_TLV_CAPA, 32)) {
                    goto parse_out;
                }
                for (i = 0; i < 32; i++) {
                    if ((le32toh(capa->api_capa) & (1 << i)) == 0)
                        continue;
                    setbit(sc->sc_enabled_capa, i + (32 * idx));
                }
                break;
            }
                
            case IWM_UCODE_TLV_CMD_VERSIONS:
                if (tlv_len % sizeof(struct iwm_fw_cmd_version)) {
                    tlv_len /= sizeof(struct iwm_fw_cmd_version);
                    tlv_len *= sizeof(struct iwm_fw_cmd_version);
                }
                if (sc->n_cmd_versions != 0) {
                    err = EINVAL;
                    goto parse_out;
                }
                if (tlv_len > sizeof(sc->cmd_versions)) {
                    err = EINVAL;
                    goto parse_out;
                }
                memcpy(&sc->cmd_versions[0], tlv_data, tlv_len);
                sc->n_cmd_versions = tlv_len / sizeof(struct iwm_fw_cmd_version);
                break;
            case IWM_UCODE_TLV_SDIO_ADMA_ADDR:
            case IWM_UCODE_TLV_FW_GSCAN_CAPA:
                /* ignore, not used by current driver */
                break;
                
            case IWM_UCODE_TLV_SEC_RT_USNIFFER:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_TYPE_REGULAR_USNIFFER, (uint8_t*)tlv_data,
                                                 tlv_len);
                if (err)
                    goto parse_out;
                break;
                
            case IWM_UCODE_TLV_PAGING:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                paging_mem_size = le32toh(*(const uint32_t *)tlv_data);
                
                DPRINTF(("%s: Paging: paging enabled (size = %u bytes)\n",
                      DEVNAME(sc), paging_mem_size));
                if (paging_mem_size > IWM_MAX_PAGING_IMAGE_SIZE) {
                    XYLog("%s: Driver only supports up to %u"
                          " bytes for paging image (%u requested)\n",
                          DEVNAME(sc), IWM_MAX_PAGING_IMAGE_SIZE,
                          paging_mem_size);
                    err = EINVAL;
                    goto out;
                }
                if (paging_mem_size & (IWM_FW_PAGING_SIZE - 1)) {
                    XYLog("%s: Paging: image isn't multiple of %u\n",
                          DEVNAME(sc), IWM_FW_PAGING_SIZE);
                    err = EINVAL;
                    goto out;
                }
                
                fw->fw_sects[IWM_UCODE_TYPE_REGULAR].paging_mem_size =
                paging_mem_size;
                usniffer_img = IWM_UCODE_TYPE_REGULAR_USNIFFER;
                fw->fw_sects[usniffer_img].paging_mem_size =
                paging_mem_size;
                break;
                
            case IWM_UCODE_TLV_N_SCAN_CHANNELS:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_n_scan_channels =
                le32toh(*(uint32_t *)tlv_data);
                if (sc->sc_capa_n_scan_channels > IWM_MAX_SCAN_CHANNELS) {
                    err = ERANGE;
                    goto parse_out;
                }
                break;
                
            case IWM_UCODE_TLV_FW_VERSION:
                if (tlv_len != sizeof(uint32_t) * 3) {
                    err = EINVAL;
                    goto parse_out;
                }
                iwm_fw_version_str(sc->sc_fwver, sizeof(sc->sc_fwver),
                                   le32toh(((uint32_t *)tlv_data)[0]),
                                   le32toh(((uint32_t *)tlv_data)[1]),
                                   le32toh(((uint32_t *)tlv_data)[2]));
                break;
                
            case IWM_UCODE_TLV_FW_DBG_DEST:
            case IWM_UCODE_TLV_FW_DBG_CONF:
            case IWM_UCODE_TLV_UMAC_DEBUG_ADDRS:
            case IWM_UCODE_TLV_LMAC_DEBUG_ADDRS:
            case IWM_UCODE_TLV_TYPE_DEBUG_INFO:
            case IWM_UCODE_TLV_TYPE_BUFFER_ALLOCATION:
            case IWM_UCODE_TLV_TYPE_HCMD:
            case IWM_UCODE_TLV_TYPE_REGIONS:
            case IWM_UCODE_TLV_TYPE_TRIGGERS:
                break;

            case IWM_UCODE_TLV_HW_TYPE:
                break;
                
            case IWM_UCODE_TLV_FW_MEM_SEG:
                break;
                /* undocumented TLVs found in iwm-9000-43 image */
            case 0x1000003:
            case 0x1000004:
                break;
            case 52://IWL_UCODE_TLV_IML
            case 53://IWL_UCODE_TLV_FW_FMAC_API_VERSION
            case 57://IWL_UCODE_TLV_FW_RECOVERY_INFO
            case 59://IWL_UCODE_TLV_FW_FMAC_RECOVERY_INFO
                break;
            case 60: {//IWL_UCODE_TLV_FW_FSEQ_VERSION
                typedef struct {
                    u8 version[32];
                    u8 sha1[20];
                } SEQVER, *PSEQVER;
                PSEQVER fseq_ver = (PSEQVER)tlv_data;
                
                if (tlv_len != sizeof(SEQVER)) {
                    err = EINVAL;
                    goto parse_out;
                }
                XYLog("TLV_FW_FSEQ_VERSION: %s\n",
                         fseq_ver->version);
            }
                break;
            /* TLVs 0x1000-0x2000 are for internal driver usage */
            case 0x1000://IWL_UCODE_TLV_FW_DBG_DUMP_LST
                
                break;
                
            default:
                err = EINVAL;
                goto parse_out;
        }
        
        /*
         * Check for size_t overflow and ignore missing padding at
         * end of firmware file.
         */
        if (roundup(tlv_len, 4) > len)
            break;
        
        len -= roundup(tlv_len, 4);
        data += roundup(tlv_len, 4);
    }
    
    _KASSERT(err == 0);
    
parse_out:
    if (err) {
        XYLog("%s: firmware parse error %d, "
              "section type %d\n", DEVNAME(sc), err, tlv_type);
    }
    
out:
    if (err) {
        fw->fw_status = IWM_FW_STATUS_NONE;
        if (fw->fw_rawdata != NULL)
            iwm_fw_info_free(fw);
    } else
        fw->fw_status = IWM_FW_STATUS_DONE;
    wakeupOn(&sc->sc_fw);
    
    OSSafeReleaseNULL(fwData);
    return err;
}

int ItlIwm::
iwm_post_alive(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int nwords;
    int err, chnl;
    uint32_t base;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    base = iwm_read_prph(sc, IWM_SCD_SRAM_BASE_ADDR);
    
    iwm_ict_reset(sc);
    
    iwm_nic_unlock(sc);
    
    /* Clear TX scheduler state in SRAM. */
    nwords = (IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND -
              IWM_SCD_CONTEXT_MEM_LOWER_BOUND)
    / sizeof(uint32_t);
    err = iwm_write_mem(sc,
                        sc->sched_base + IWM_SCD_CONTEXT_MEM_LOWER_BOUND,
                        NULL, nwords);
    if (err)
        return err;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwm_write_prph(sc, IWM_SCD_DRAM_BASE_ADDR, sc->sched_dma.paddr >> 10);
    
    iwm_write_prph(sc, IWM_SCD_CHAINEXT_EN, 0);
    
    /* enable command channel */
    err = iwm_enable_ac_txq(sc, sc->cmdqid, IWM_TX_FIFO_CMD);
    if (err) {
        iwm_nic_unlock(sc);
        return err;
    }
    
    /* Activate TX scheduler. */
    iwm_write_prph(sc, IWM_SCD_TXFACT, 0xff);
    
    /* Enable DMA channels. */
    for (chnl = 0; chnl < IWM_FH_TCSR_CHNL_NUM; chnl++) {
        IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(chnl),
                  IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
                  IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE);
    }
    
    IWM_SETBITS(sc, IWM_FH_TX_CHICKEN_BITS_REG,
                IWM_FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN);
    
    iwm_nic_unlock(sc);
    
    /* Enable L1-Active */
    if (sc->sc_device_family < IWM_DEVICE_FAMILY_8000)
        iwm_clear_bits_prph(sc, IWM_APMG_PCIDEV_STT_REG,
                            IWM_APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
    
    return err;
}

uint8_t ItlIwm::
iwm_fw_valid_tx_ant(struct iwm_softc *sc)
{
    uint8_t tx_ant;
    
    tx_ant = ((sc->sc_fw_phy_config & IWM_FW_PHY_CFG_TX_CHAIN)
              >> IWM_FW_PHY_CFG_TX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_tx_ant)
        tx_ant &= sc->sc_nvm.valid_tx_ant;
    
    return tx_ant;
}

uint8_t ItlIwm::
iwm_fw_valid_rx_ant(struct iwm_softc *sc)
{
    uint8_t rx_ant;
    
    rx_ant = ((sc->sc_fw_phy_config & IWM_FW_PHY_CFG_RX_CHAIN)
              >> IWM_FW_PHY_CFG_RX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_rx_ant)
        rx_ant &= sc->sc_nvm.valid_rx_ant;
    
    return rx_ant;
}

uint32_t ItlIwm::
iwm_get_tx_ant(struct iwm_softc *sc, struct ieee80211_node *ni,
               int type, struct ieee80211_frame *wh)
{
    if (IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) &&
        !ItlIwm::iwm_coex_is_shared_ant_avail(sc))
        return sc->non_shared_ant << RATE_MCS_ANT_POS;
    
    if (!IEEE80211_IS_MULTICAST(wh->i_addr1) && type == IEEE80211_FC0_TYPE_DATA)
        return ((1 << sc->sc_tx_ant) << RATE_MCS_ANT_POS);
    
    return ((1 << sc->sc_mgmt_last_antenna_idx) << RATE_MCS_ANT_POS);
}

void ItlIwm::
iwm_toggle_tx_ant(struct iwm_softc *sc, uint8_t *ant)
{
    int i;
    uint8_t ind = *ant;
    uint8_t valid = iwm_fw_valid_tx_ant(sc);
    for (i = 0; i < IWM_RATE_MCS_ANT_NUM; i++) {
        ind = (ind + 1) % IWM_RATE_MCS_ANT_NUM;
        if (valid & (1 << ind))
            break;
    }
    
    *ant = ind;
}

int ItlIwm::
iwm_firmware_load_sect(struct iwm_softc *sc, uint32_t dst_addr,
                       const uint8_t *section, uint32_t byte_cnt)
{
    int err = EINVAL;
    uint32_t chunk_sz, offset;
    
    chunk_sz = MIN(IWM_FH_MEM_TB_MAX_LENGTH, byte_cnt);
    
    for (offset = 0; offset < byte_cnt; offset += chunk_sz) {
        uint32_t addr, len;
        const uint8_t *data;
        
        addr = dst_addr + offset;
        len = MIN(chunk_sz, byte_cnt - offset);
        data = section + offset;
        
        err = iwm_firmware_load_chunk(sc, addr, data, len);
        if (err)
            break;
    }
    
    return err;
}

int ItlIwm::
iwm_firmware_load_chunk(struct iwm_softc *sc, uint32_t dst_addr,
                        const uint8_t *chunk, uint32_t byte_cnt)
{
    struct iwm_dma_info *dma = &sc->fw_dma;
    int err;
    
    /* Copy firmware chunk into pre-allocated DMA-safe memory. */
    memcpy(dma->vaddr, chunk, byte_cnt);
    //        bus_dmamap_sync(sc->sc_dmat,
    //            dma->map, 0, byte_cnt, BUS_DMASYNC_PREWRITE);
    
    if (dst_addr >= IWM_FW_MEM_EXTENDED_START &&
        dst_addr <= IWM_FW_MEM_EXTENDED_END)
        iwm_set_bits_prph(sc, IWM_LMPM_CHICK,
                          IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE);
    
    sc->sc_fw_chunk_done = 0;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
              IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);
    IWM_WRITE(sc, IWM_FH_SRVC_CHNL_SRAM_ADDR_REG(IWM_FH_SRVC_CHNL),
              dst_addr);
    IWM_WRITE(sc, IWM_FH_TFDIB_CTRL0_REG(IWM_FH_SRVC_CHNL),
              dma->paddr & IWM_FH_MEM_TFDIB_DRAM_ADDR_LSB_MSK);
    IWM_WRITE(sc, IWM_FH_TFDIB_CTRL1_REG(IWM_FH_SRVC_CHNL),
              (iwm_get_dma_hi_addr(dma->paddr)
               << IWM_FH_MEM_TFDIB_REG1_ADDR_BITSHIFT) | byte_cnt);
    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_BUF_STS_REG(IWM_FH_SRVC_CHNL),
              1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM |
              1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX |
              IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID);
    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
              IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE    |
              IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE |
              IWM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD);
    
    iwm_nic_unlock(sc);
    
    /* Wait for this segment to load. */
    err = 0;
    while (!sc->sc_fw_chunk_done) {
        err = tsleep_nsec(&sc->sc_fw, 0, "iwmfw", SEC_TO_NSEC(1));
        if (err)
            break;
    }
    
    if (!sc->sc_fw_chunk_done)
        XYLog("%s: fw chunk addr 0x%x len %d failed to load\n",
              DEVNAME(sc), dst_addr, byte_cnt);
    
    if (dst_addr >= IWM_FW_MEM_EXTENDED_START &&
        dst_addr <= IWM_FW_MEM_EXTENDED_END) {
        iwm_clear_bits_prph(sc, IWM_LMPM_CHICK,
                            IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE);
    }
    
    return err;
}

int ItlIwm::
iwm_load_firmware_7000(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    struct iwm_fw_sects *fws;
    int err, i;
    void *data;
    uint32_t dlen;
    uint32_t offset;
    
    fws = &sc->sc_fw.fw_sects[ucode_type];
    for (i = 0; i < fws->fw_count; i++) {
        data = fws->fw_sect[i].fws_data;
        dlen = fws->fw_sect[i].fws_len;
        offset = fws->fw_sect[i].fws_devoff;
        if (dlen > sc->sc_fwdmasegsz) {
            err = EFBIG;
        } else
            err = iwm_firmware_load_sect(sc, offset, (const uint8_t*)data, dlen);
        if (err) {
            XYLog("%s: could not load firmware chunk %u of %u\n",
                  DEVNAME(sc), i, fws->fw_count);
            return err;
        }
    }
    
    iwm_enable_interrupts(sc);
    
    IWM_WRITE(sc, IWM_CSR_RESET, 0);
    
    return 0;
}

int ItlIwm::
iwm_load_cpu_sections_8000(struct iwm_softc *sc, struct iwm_fw_sects *fws,
                           int cpu, int *first_ucode_section)
{
    int shift_param;
    int i, err = 0, sec_num = 0x1;
    uint32_t val, last_read_idx = 0;
    void *data;
    uint32_t dlen;
    uint32_t offset;
    
    if (cpu == 1) {
        shift_param = 0;
        *first_ucode_section = 0;
    } else {
        shift_param = 16;
        (*first_ucode_section)++;
    }
    
    for (i = *first_ucode_section; i < IWM_UCODE_SECT_MAX; i++) {
        last_read_idx = i;
        data = fws->fw_sect[i].fws_data;
        dlen = fws->fw_sect[i].fws_len;
        offset = fws->fw_sect[i].fws_devoff;
        
        /*
         * CPU1_CPU2_SEPARATOR_SECTION delimiter - separate between
         * CPU1 to CPU2.
         * PAGING_SEPARATOR_SECTION delimiter - separate between
         * CPU2 non paged to CPU2 paging sec.
         */
        if (!data || offset == IWM_CPU1_CPU2_SEPARATOR_SECTION ||
            offset == IWM_PAGING_SEPARATOR_SECTION)
            break;
        
        if (dlen > sc->sc_fwdmasegsz) {
            err = EFBIG;
        } else
            err = iwm_firmware_load_sect(sc, offset, (const uint8_t*)data, dlen);
        if (err) {
            XYLog("%s: could not load firmware chunk %d "
                  "(error %d)\n", DEVNAME(sc), i, err);
            return err;
        }
        
        /* Notify the ucode of the loaded section number and status */
        if (iwm_nic_lock(sc)) {
            val = IWM_READ(sc, IWM_FH_UCODE_LOAD_STATUS);
            val = val | (sec_num << shift_param);
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, val);
            sec_num = (sec_num << 1) | 0x1;
            iwm_nic_unlock(sc);
        } else {
            err = EBUSY;
            XYLog("%s: could not load firmware chunk %d "
                  "(error %d)\n", DEVNAME(sc), i, err);
            return err;
        }
    }
    
    *first_ucode_section = last_read_idx;
    
    if (iwm_nic_lock(sc)) {
        if (cpu == 1)
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, 0xFFFF);
        else
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, 0xFFFFFFFF);
        iwm_nic_unlock(sc);
    } else {
        err = EBUSY;
        XYLog("%s: could not finalize firmware loading (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    return 0;
}

int ItlIwm::
iwm_load_firmware_8000(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    struct iwm_fw_sects *fws;
    int err = 0;
    int first_ucode_section;
    
    fws = &sc->sc_fw.fw_sects[ucode_type];
    
    /* configure the ucode to be ready to get the secured image */
    /* release CPU reset */
    if (iwm_nic_lock(sc)) {
        iwm_write_prph(sc, IWM_RELEASE_CPU_RESET,
                       IWM_RELEASE_CPU_RESET_BIT);
        iwm_nic_unlock(sc);
    }
    
    /* load to FW the binary Secured sections of CPU1 */
    err = iwm_load_cpu_sections_8000(sc, fws, 1, &first_ucode_section);
    if (err)
        return err;
    
    /* load to FW the binary sections of CPU2 */
    err = iwm_load_cpu_sections_8000(sc, fws, 2, &first_ucode_section);
    if (err)
        return err;
    
    iwm_enable_interrupts(sc);
    return 0;
}

int ItlIwm::
iwm_load_firmware(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    XYLog("%s\n", __FUNCTION__);
    int err/*, w*/;
    
    sc->sc_uc.uc_intr = 0;
    
    if (sc->sc_device_family >= IWM_DEVICE_FAMILY_8000)
        err = iwm_load_firmware_8000(sc, ucode_type);
    else
        err = iwm_load_firmware_7000(sc, ucode_type);
    
    if (err)
        return err;
    
    /* wait for the firmware to load */
//    for (w = 0; !sc->sc_uc.uc_intr && w < 10; w++) {
//        err = tsleep_nsec(&sc->sc_uc, 0, "iwmuc", MSEC_TO_NSEC(100));
//    }
    err = tsleep_nsec(&sc->sc_uc, 0, "iwmuc", SEC_TO_NSEC(1));
    if (err || !sc->sc_uc.uc_ok)
        XYLog("%s: could not load firmware\n", DEVNAME(sc));
    
    return err;
}

int ItlIwm::
iwm_start_fw(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    XYLog("%s ucode_type=%d\n", __FUNCTION__, ucode_type);
    int err;
    
    IWM_WRITE(sc, IWM_CSR_INT, ~0);
    
    err = iwm_nic_init(sc);
    if (err) {
        XYLog("%s: unable to init nic\n", DEVNAME(sc));
        return err;
    }
    
    /* make sure rfkill handshake bits are cleared */
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR,
              IWM_CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
    
    /* clear (again), then enable firwmare load interrupt */
    IWM_WRITE(sc, IWM_CSR_INT, ~0);
    iwm_enable_fwload_interrupt(sc);
    
    /* really make sure rfkill handshake bits are cleared */
    /* maybe we should write a few times more?  just to make sure */
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    
    return iwm_load_firmware(sc, ucode_type);
}

int ItlIwm::
iwm_send_tx_ant_cfg(struct iwm_softc *sc, uint8_t valid_tx_ant)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_tx_ant_cfg_cmd tx_ant_cmd = {
        .valid = htole32(valid_tx_ant),
    };
    
    return iwm_send_cmd_pdu(sc, IWM_TX_ANT_CONFIGURATION_CMD,
                            0, sizeof(tx_ant_cmd), &tx_ant_cmd);
}

int ItlIwm::
iwm_load_ucode_wait_alive(struct iwm_softc *sc,
                          enum iwm_ucode_type ucode_type)
{
    XYLog("%s ucode_type=%d\n", __FUNCTION__, ucode_type);
    enum iwm_ucode_type old_type = sc->sc_uc_current;
    struct iwm_fw_sects *fw = &sc->sc_fw.fw_sects[ucode_type];
    int err;
    
    err = iwm_read_firmware(sc, ucode_type);
    if (err)
        return err;
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
        sc->cmdqid = IWM_DQA_CMD_QUEUE;
    else
        sc->cmdqid = IWM_CMD_QUEUE;
    
    sc->sc_uc_current = ucode_type;
    err = iwm_start_fw(sc, ucode_type);
    if (err) {
        sc->sc_uc_current = old_type;
        return err;
    }
    
    err = iwm_post_alive(sc);
    if (err)
        return err;
    
    /*
     * configure and operate fw paging mechanism.
     * driver configures the paging flow only once, CPU2 paging image
     * included in the IWM_UCODE_INIT image.
     */
    if (fw->paging_mem_size) {
        err = iwm_save_fw_paging(sc, fw);
        if (err) {
            XYLog("%s: failed to save the FW paging image\n",
                  DEVNAME(sc));
            return err;
        }
        
        err = iwm_send_paging_cmd(sc, fw);
        if (err) {
            XYLog("%s: failed to send the paging cmd\n",
                  DEVNAME(sc));
            iwm_free_fw_paging(sc);
            return err;
        }
    }
    
    return 0;
}

int ItlIwm::
iwm_run_init_mvm_ucode(struct iwm_softc *sc, int justnvm)
{
    XYLog("%s justnvm=%d\n", __FUNCTION__, justnvm);
    const int wait_flags = (IWM_INIT_COMPLETE | IWM_CALIB_COMPLETE);
    int err;
    
    if ((sc->sc_flags & IWM_FLAG_RFKILL) && !justnvm) {
        XYLog("%s: radio is disabled by hardware switch\n",
              DEVNAME(sc));
        return EPERM;
    }
    
    sc->sc_init_complete = 0;
    err = iwm_load_ucode_wait_alive(sc, IWM_UCODE_TYPE_INIT);
    if (err) {
        XYLog("%s: failed to load init firmware\n", DEVNAME(sc));
        return err;
    }
    
    if (sc->sc_device_family < IWM_DEVICE_FAMILY_8000) {
        err = iwm_send_bt_init_conf(sc);
        if (err) {
            XYLog("%s: could not init bt coex (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
    }
    
    if (justnvm) {
        err = iwm_nvm_init(sc);
        if (err) {
            XYLog("%s: failed to read nvm\n", DEVNAME(sc));
            return err;
        }
        
        if (IEEE80211_ADDR_EQ(etheranyaddr, sc->sc_ic.ic_myaddr))
            IEEE80211_ADDR_COPY(sc->sc_ic.ic_myaddr,
                                sc->sc_nvm.hw_addr);
        
        return 0;
    }
    
    err = iwm_sf_config(sc, IWM_SF_INIT_OFF);
    if (err)
        return err;
    
    /* Send TX valid antennas before triggering calibrations */
    err = iwm_send_tx_ant_cfg(sc, iwm_fw_valid_tx_ant(sc));
    if (err)
        return err;
    
    /*
     * Send phy configurations command to init uCode
     * to start the 16.0 uCode init image internal calibrations.
     */
    err = iwm_send_phy_cfg_cmd(sc);
    if (err)
        return err;
    
    /*
     * Nothing to do but wait for the init complete and phy DB
     * notifications from the firmware.
     */
//    while ((sc->sc_init_complete & wait_flags) != wait_flags) {
//        err = tsleep_nsec(&sc->sc_init_complete, 0, "iwminit",
//                          SEC_TO_NSEC(2));
//        if (err)
//            break;
//    }
    err = tsleep_nsec(&sc->sc_init_complete, 0, "iwminit", SEC_TO_NSEC(2));
    
    return err;
}

int ItlIwm::
iwm_config_ltr(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_ltr_config_cmd cmd = {
        .flags = htole32(IWM_LTR_CFG_FLAG_FEATURE_ENABLE),
    };
    
    if (!sc->sc_ltr_enabled)
        return 0;
    
    return iwm_send_cmd_pdu(sc, IWM_LTR_CONFIG, 0, sizeof(cmd), &cmd);
}
