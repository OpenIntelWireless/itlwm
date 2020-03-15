//
//  fw.cpp
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
#include "FwData.h"

int itlwm::
iwm_is_mimo_ht_plcp(uint8_t ht_plcp)
{
    return (ht_plcp != IWM_RATE_HT_SISO_MCS_INV_PLCP &&
            (ht_plcp & IWM_RATE_HT_MCS_NSS_MSK));
}

int itlwm::
iwm_is_mimo_mcs(int mcs)
{
    int ridx = iwm_mcs2ridx[mcs];
    return iwm_is_mimo_ht_plcp(iwm_rates[ridx].ht_plcp);
    
}

int itlwm::
iwm_store_cscheme(struct iwm_softc *sc, uint8_t *data, size_t dlen)
{
    struct iwm_fw_cscheme_list *l = (struct iwm_fw_cscheme_list *)data;
    
    if (dlen < sizeof(*l) ||
        dlen < sizeof(l->size) + l->size * sizeof(*l->cs))
        return EINVAL;
    
    /* we don't actually store anything for now, always use s/w crypto */
    
    return 0;
}

int itlwm::
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

struct iwm_tlv_calib_data {
    uint32_t ucode_type;
    struct iwm_tlv_calib_ctrl calib;
} __packed;

int itlwm::
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

void itlwm::
iwm_fw_info_free(struct iwm_fw_info *fw)
{
    free(fw->fw_rawdata, M_DEVBUF, fw->fw_rawsize);
    fw->fw_rawdata = NULL;
    fw->fw_rawsize = 0;
    /* don't touch fw->fw_status */
    memset(fw->fw_sects, 0, sizeof(fw->fw_sects));
}

void itlwm::
onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context)
{
    XYLog("onLoadFW callback ret=0x%08x length=%d", result, resourceDataLength);
    ResourceCallbackContext *resourceContxt = (ResourceCallbackContext*)context;
    IOLockLock(resourceContxt->context->fwLoadLock);
    if (resourceDataLength > 0) {
        XYLog("onLoadFW return success");
        resourceContxt->resource = OSData::withBytes(resourceData, resourceDataLength);
    }
    IOLockUnlock(resourceContxt->context->fwLoadLock);
    IOLockWakeup(resourceContxt->context->fwLoadLock, resourceContxt->context, false);
    XYLog("onLoadFW wakeupOn");
}

int itlwm::
iwm_read_firmware(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    struct iwm_fw_info *fw = &sc->sc_fw;
    struct iwm_tlv_ucode_header *uhdr;
    struct iwm_ucode_tlv tlv;
    uint32_t tlv_type;
    uint8_t *data;
    int err;
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
    IOLockLock(fwLoadLock);
    ResourceCallbackContext context =
    {
        .context = this,
        .resource = NULL
    };
    IOReturn ret = OSKextRequestResource(OSKextGetCurrentIdentifier(), sc->sc_fwname, onLoadFW, &context, NULL);
    IOLockSleep(fwLoadLock, this, 0);
    IOLockUnlock(fwLoadLock);
    if (context.resource == NULL) {
        XYLog("%s resource load fail.\n", sc->sc_fwname);
        goto out;
    }
    fw->fw_rawdata = (u_char*)context.resource->getBytesNoCopy();
    fw->fw_rawsize = context.resource->getLength();
//    fwData = getFWDescByName(sc->sc_fwname);
//    if (fwData == NULL) {
//        XYLog("%s resource load fail.\n", sc->sc_fwname);
//        goto out;
//    }
//    fw->fw_rawdata = (u_char*)fwData->getBytesNoCopy();
//    fw->fw_rawsize = fwData->getLength();
    XYLog("load firmware done\n");
    sc->sc_capaflags = 0;
    sc->sc_capa_n_scan_channels = IWM_DEFAULT_SCAN_CHANNELS;
    memset(sc->sc_enabled_capa, 0, sizeof(sc->sc_enabled_capa));
    memset(sc->sc_fw_mcc, 0, sizeof(sc->sc_fw_mcc));
    
    uhdr = (struct iwm_tlv_ucode_header *)fw->fw_rawdata;
    if (*(uint32_t *)fw->fw_rawdata != 0
        || le32toh(uhdr->magic) != IWM_TLV_UCODE_MAGIC) {
        XYLog("%s: invalid firmware %s\n",
              DEVNAME(sc), sc->sc_fwname);
        err = EINVAL;
        goto out;
    }
    
    snprintf(sc->sc_fwver, sizeof(sc->sc_fwver), "%d.%d (API ver %d)",
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
                if (tlv_len != sizeof(*api)) {
                    err = EINVAL;
                    goto parse_out;
                }
                api = (struct iwm_ucode_api *)tlv_data;
                /* Flags may exceed 32 bits in future firmware. */
                if (le32toh(api->api_index) > 0) {
                    goto parse_out;
                }
                sc->sc_ucode_api = le32toh(api->api_flags);
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
                
            case 48: /* undocumented TLV */
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
                
            case IWM_UCODE_TLV_N_SCAN_CHANNELS:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_n_scan_channels =
                le32toh(*(uint32_t *)tlv_data);
                break;
                
            case IWM_UCODE_TLV_FW_VERSION:
                if (tlv_len != sizeof(uint32_t) * 3) {
                    err = EINVAL;
                    goto parse_out;
                }
                snprintf(sc->sc_fwver, sizeof(sc->sc_fwver),
                         "%d.%d.%d",
                         le32toh(((uint32_t *)tlv_data)[0]),
                         le32toh(((uint32_t *)tlv_data)[1]),
                         le32toh(((uint32_t *)tlv_data)[2]));
                break;
                
            case IWM_UCODE_TLV_FW_MEM_SEG:
                break;
                
            default:
                err = EINVAL;
                goto parse_out;
        }
        
        len -= roundup(tlv_len, 4);
        data += roundup(tlv_len, 4);
    }
    
    _KASSERT(err == 0);
    
parse_out:
    if (err) {
        XYLog("%s: firmware parse error %d, "
              "section type %d\n", DEVNAME(sc), err, tlv_type);
    }
    
    if (!(sc->sc_capaflags & IWM_UCODE_TLV_FLAGS_PM_CMD_SUPPORT)) {
        XYLog("%s: device uses unsupported power ops\n", DEVNAME(sc));
        err = ENOTSUP;
    }
    
out:
    if (err) {
        fw->fw_status = IWM_FW_STATUS_NONE;
        if (fw->fw_rawdata != NULL)
            iwm_fw_info_free(fw);
    } else
        fw->fw_status = IWM_FW_STATUS_DONE;
    wakeupOn(&sc->sc_fw);
    
    return err;
}

int itlwm::
iwm_post_alive(struct iwm_softc *sc)
{
    int nwords;
    int err, chnl;
    uint32_t base;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    base = iwm_read_prph(sc, IWM_SCD_SRAM_BASE_ADDR);
    
    iwm_ict_reset(sc);
    
    /* Clear TX scheduler state in SRAM. */
    nwords = (IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND -
              IWM_SCD_CONTEXT_MEM_LOWER_BOUND)
    / sizeof(uint32_t);
    err = iwm_write_mem(sc,
                        sc->sched_base + IWM_SCD_CONTEXT_MEM_LOWER_BOUND,
                        NULL, nwords);
    if (err)
        goto out;
    
    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwm_write_prph(sc, IWM_SCD_DRAM_BASE_ADDR, sc->sched_dma.paddr >> 10);
    
    iwm_write_prph(sc, IWM_SCD_CHAINEXT_EN, 0);
    
    /* enable command channel */
    err = iwm_enable_txq(sc, 0 /* unused */, IWM_CMD_QUEUE, 7);
    if (err)
        goto out;
    
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
    
    /* Enable L1-Active */
    if (sc->sc_device_family != IWM_DEVICE_FAMILY_8000)
        iwm_clear_bits_prph(sc, IWM_APMG_PCIDEV_STT_REG,
                            IWM_APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
    
out:
    iwm_nic_unlock(sc);
    return err;
}

uint8_t itlwm::
iwm_fw_valid_tx_ant(struct iwm_softc *sc)
{
    uint8_t tx_ant;
    
    tx_ant = ((sc->sc_fw_phy_config & IWM_FW_PHY_CFG_TX_CHAIN)
              >> IWM_FW_PHY_CFG_TX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_tx_ant)
        tx_ant &= sc->sc_nvm.valid_tx_ant;
    
    return tx_ant;
}

uint8_t itlwm::
iwm_fw_valid_rx_ant(struct iwm_softc *sc)
{
    uint8_t rx_ant;
    
    rx_ant = ((sc->sc_fw_phy_config & IWM_FW_PHY_CFG_RX_CHAIN)
              >> IWM_FW_PHY_CFG_RX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_rx_ant)
        rx_ant &= sc->sc_nvm.valid_rx_ant;
    
    return rx_ant;
}

int itlwm::
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

int itlwm::
iwm_firmware_load_chunk(struct iwm_softc *sc, uint32_t dst_addr,
                        const uint8_t *chunk, uint32_t byte_cnt)
{
    struct iwm_dma_info *dma = &sc->fw_dma;
    int err;
    
    /* Copy firmware chunk into pre-allocated DMA-safe memory. */
    memcpy(dma->vaddr, chunk, byte_cnt);
    //    bus_dmamap_sync(sc->sc_dmat,
    //        dma->map, 0, byte_cnt, BUS_DMASYNC_PREWRITE);
    
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

int itlwm::
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
    
    IWM_WRITE(sc, IWM_CSR_RESET, 0);
    
    return 0;
}

int itlwm::
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

int itlwm::
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
    return iwm_load_cpu_sections_8000(sc, fws, 2, &first_ucode_section);
}

int itlwm::
iwm_load_firmware(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    int err, w;
    
    sc->sc_uc.uc_intr = 0;
    
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000)
        err = iwm_load_firmware_8000(sc, ucode_type);
    else
        err = iwm_load_firmware_7000(sc, ucode_type);
    
    if (err)
        return err;
    
    /* wait for the firmware to load */
    for (w = 0; !sc->sc_uc.uc_intr && w < 10; w++) {
        err = tsleep_nsec(&sc->sc_uc, 0, "iwmuc", MSEC_TO_NSEC(100));
    }
    if (err || !sc->sc_uc.uc_ok)
        XYLog("%s: could not load firmware\n", DEVNAME(sc));
    
    return err;
}

int itlwm::
iwm_start_fw(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
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
    
    /* clear (again), then enable host interrupts */
    IWM_WRITE(sc, IWM_CSR_INT, ~0);
    iwm_enable_interrupts(sc);
    
    /* really make sure rfkill handshake bits are cleared */
    /* maybe we should write a few times more?  just to make sure */
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    
    return iwm_load_firmware(sc, ucode_type);
}

int itlwm::
iwm_send_tx_ant_cfg(struct iwm_softc *sc, uint8_t valid_tx_ant)
{
    XYLog("%s\n", __func__);
    struct iwm_tx_ant_cfg_cmd tx_ant_cmd = {
        .valid = htole32(valid_tx_ant),
    };
    
    return iwm_send_cmd_pdu(sc, IWM_TX_ANT_CONFIGURATION_CMD,
                            0, sizeof(tx_ant_cmd), &tx_ant_cmd);
}

int itlwm::
iwm_load_ucode_wait_alive(struct iwm_softc *sc,
                          enum iwm_ucode_type ucode_type)
{
    XYLog("%s\n", __func__);
    enum iwm_ucode_type old_type = sc->sc_uc_current;
    int err;
    
    err = iwm_read_firmware(sc, ucode_type);
    if (err)
        return err;
    
    sc->sc_uc_current = ucode_type;
    err = iwm_start_fw(sc, ucode_type);
    if (err) {
        sc->sc_uc_current = old_type;
        return err;
    }
    
    return iwm_post_alive(sc);
}

int itlwm::
iwm_run_init_mvm_ucode(struct iwm_softc *sc, int justnvm)
{
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
    
    err = iwm_send_bt_init_conf(sc);
    if (err)
        return err;
    
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
    
    XYLog("%s wait for sc_init_complete\n", __func__);
    
    /*
     * Nothing to do but wait for the init complete and phy DB
     * notifications from the firmware.
     */
//    while ((sc->sc_init_complete & wait_flags) != wait_flags) {
//        err = tsleep_nsec(&sc->sc_init_complete, 0, "iwminit",
//            SEC_TO_NSEC(2));
//        if (err)
//            break;
//    }
    err = tsleep_nsec(&sc->sc_init_complete, 0, "iwminit",
    SEC_TO_NSEC(2));
    
    XYLog("%s done\n", __func__);
    
    return err;
}
