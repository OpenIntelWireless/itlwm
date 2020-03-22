//
//  tx.cpp
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

void itlwm::
iwm_free_tx_ring(iwm_softc *sc, struct iwm_tx_ring *ring)
{
    int i;
    
    iwm_dma_contig_free(&ring->desc_dma);
    iwm_dma_contig_free(&ring->cmd_dma);
    
    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            freePacket(data->m);
        }
        if (data->map != NULL)
            bus_dmamap_destroy(sc->sc_dmat, data->map);
    }
}

void itlwm::
iwm_reset_tx_ring(struct iwm_softc *sc, struct iwm_tx_ring *ring)
{
    int i;
    
    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
            //                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
            //            bus_dmamap_unload(sc->sc_dmat, data->map);
            freePacket(data->m);
            data->m = NULL;
        }
    }
    /* Clear TX descriptors. */
    memset(ring->desc, 0, ring->desc_dma.size);
    //    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map, 0,
    //        ring->desc_dma.size, BUS_DMASYNC_PREWRITE);
    sc->qfullmsk &= ~(1 << ring->qid);
    /* 7000 family NICs are locked while commands are in progress. */
    if (ring->qid == sc->cmdqid && ring->queued > 0) {
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
            iwm_nic_unlock(sc);
    }
    ring->queued = 0;
    ring->cur = 0;
    ring->tail = 0;
}

int itlwm::
iwm_alloc_tx_ring(iwm_softc *sc, struct iwm_tx_ring *ring, int qid)
{
    bus_addr_t paddr;
    bus_size_t size;
    int i, err;
    
    ring->qid = qid;
    ring->queued = 0;
    ring->cur = 0;
    ring->tail = 0;
    
    /* Allocate TX descriptors (256-byte aligned). */
    size = IWM_TX_RING_COUNT * sizeof (struct iwm_tfd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, NULL, size, 256);
    if (err) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    ring->desc = (struct iwm_tfd *)ring->desc_dma.vaddr;
    
    /*
     * There is no need to allocate DMA buffers for unused rings.
     * 7k/8k/9k hardware supports up to 31 Tx rings which is more
     * than we currently need.
     *
     * In DQA mode we use 1 command queue + 4 DQA mgmt/data queues.
     * The command is queue 0 (sc->txq[0]), and 4 mgmt/data frame queues
     * are sc->tqx[IWM_DQA_MIN_MGMT_QUEUE + ac], i.e. sc->txq[5:8],
     * in order to provide one queue per EDCA category.
     *
     * In non-DQA mode, we use rings 0 through 9 (0-3 are EDCA, 9 is cmd).
     *
     * Tx aggregation will require additional queues (one queue per TID
     * for which aggregation is enabled) but we do not implement this yet.
     *
     * Unfortunately, we cannot tell if DQA will be used until the
     * firmware gets loaded later, so just allocate sufficient rings
     * in order to satisfy both cases.
     */
    if (qid > IWM_CMD_QUEUE)
        return 0;
    
    size = IWM_TX_RING_COUNT * sizeof(struct iwm_device_cmd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma, NULL, size, 4);
    if (err) {
        XYLog("%s: could not allocate cmd DMA memory\n", DEVNAME(sc));
        goto fail;
    }
    ring->cmd = (struct iwm_device_cmd*)ring->cmd_dma.vaddr;
    
    paddr = ring->cmd_dma.paddr;
    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];
        size_t mapsize;
        
        data->cmd_paddr = paddr;
        data->scratch_paddr = paddr + sizeof(struct iwm_cmd_header)
        + offsetof(struct iwm_tx_cmd, scratch);
        paddr += sizeof(struct iwm_device_cmd);
        
        /* FW commands may require more mapped space than packets. */
        if (qid == IWM_CMD_QUEUE || qid == IWM_DQA_CMD_QUEUE)
            mapsize = (sizeof(struct iwm_cmd_header) +
                       IWM_MAX_CMD_PAYLOAD_SIZE);
        else
            mapsize = MCLBYTES;
        err = bus_dmamap_create(sc->sc_dmat, mapsize,
                                IWM_NUM_OF_TBS - 2, mapsize, 0, BUS_DMA_NOWAIT,
                                &data->map);
        if (err) {
            XYLog("%s: could not create TX buf DMA map\n",
                  DEVNAME(sc));
            goto fail;
        }
    }
    KASSERT(paddr == ring->cmd_dma.paddr + size, "");
    return 0;
    
fail:    iwm_free_tx_ring(sc, ring);
    return err;
}

int itlwm::
iwm_enable_ac_txq(struct iwm_softc *sc, int qid, int fifo)
{
    XYLog("%s\n", __FUNCTION__);
    iwm_nic_assert_locked(sc);
    
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, qid << 8 | 0);
    
    iwm_write_prph(sc, IWM_SCD_QUEUE_STATUS_BITS(qid),
                   (0 << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE)
                   | (1 << IWM_SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN));
    
    iwm_clear_bits_prph(sc, IWM_SCD_AGGR_SEL, (1 << qid));
    
    iwm_write_prph(sc, IWM_SCD_QUEUE_RDPTR(qid), 0);
    
    iwm_write_mem32(sc,
                    sc->sched_base + IWM_SCD_CONTEXT_QUEUE_OFFSET(qid), 0);
    
    /* Set scheduler window size and frame limit. */
    iwm_write_mem32(sc,
                    sc->sched_base + IWM_SCD_CONTEXT_QUEUE_OFFSET(qid) +
                    sizeof(uint32_t),
                    ((IWM_FRAME_LIMIT << IWM_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS) &
                     IWM_SCD_QUEUE_CTX_REG2_WIN_SIZE_MSK) |
                    ((IWM_FRAME_LIMIT
                      << IWM_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS) &
                     IWM_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK));
    
    iwm_write_prph(sc, IWM_SCD_QUEUE_STATUS_BITS(qid),
                   (1 << IWM_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
                   (fifo << IWM_SCD_QUEUE_STTS_REG_POS_TXF) |
                   (1 << IWM_SCD_QUEUE_STTS_REG_POS_WSL) |
                   IWM_SCD_QUEUE_STTS_REG_MSK);
    
    if (qid == sc->cmdqid)
        iwm_write_prph(sc, IWM_SCD_EN_CTRL,
                       iwm_read_prph(sc, IWM_SCD_EN_CTRL) | (1 << qid));
    
    return 0;
}

int itlwm::
iwm_enable_txq(struct iwm_softc *sc, int sta_id, int qid, int fifo)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_scd_txq_cfg_cmd cmd;
    int err;
    
    iwm_nic_assert_locked(sc);
    
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, qid << 8 | 0);
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.scd_queue = qid;
    cmd.enable = 1;
    cmd.sta_id = sta_id;
    cmd.tx_fifo = fifo;
    cmd.aggregate = 0;
    cmd.window = IWM_FRAME_LIMIT;
    
    err = iwm_send_cmd_pdu(sc, IWM_SCD_QUEUE_CFG, 0,
                           sizeof(cmd), &cmd);
    if (err)
        return err;
    
    return 0;
}

int itlwm::
iwm_send_update_mcc_cmd(struct iwm_softc *sc, const char *alpha2)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_mcc_update_cmd mcc_cmd;
    struct iwm_host_cmd hcmd = {
        .id = IWM_MCC_UPDATE_CMD,
        .flags = IWM_CMD_WANT_RESP,
        .data = { &mcc_cmd },
    };
    int err;
    int resp_v2 = isset(sc->sc_enabled_capa,
                        IWM_UCODE_TLV_CAPA_LAR_SUPPORT_V2);
    
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000 &&
        !sc->sc_nvm.lar_enabled) {
        return 0;
    }
    
    memset(&mcc_cmd, 0, sizeof(mcc_cmd));
    mcc_cmd.mcc = htole16(alpha2[0] << 8 | alpha2[1]);
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_WIFI_MCC_UPDATE) ||
        isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_LAR_MULTI_MCC))
        mcc_cmd.source_id = IWM_MCC_SOURCE_GET_CURRENT;
    else
        mcc_cmd.source_id = IWM_MCC_SOURCE_OLD_FW;
    
    if (resp_v2) {
        hcmd.len[0] = sizeof(struct iwm_mcc_update_cmd);
        hcmd.resp_pkt_len = sizeof(struct iwm_rx_packet) +
        sizeof(struct iwm_mcc_update_resp);
    } else {
        hcmd.len[0] = sizeof(struct iwm_mcc_update_cmd_v1);
        hcmd.resp_pkt_len = sizeof(struct iwm_rx_packet) +
        sizeof(struct iwm_mcc_update_resp_v1);
    }
    
    err = iwm_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    iwm_free_resp(sc, &hcmd);
    
    return 0;
}

void itlwm::
iwm_tt_tx_backoff(struct iwm_softc *sc, uint32_t backoff)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_host_cmd cmd = {
        .id = IWM_REPLY_THERMAL_MNG_BACKOFF,
        .len = { sizeof(uint32_t), },
        .data = { &backoff, },
    };
    
    iwm_send_cmd(sc, &cmd);
}

void itlwm::
iwm_free_fw_paging(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int i;
    
    if (sc->fw_paging_db[0].fw_paging_block.vaddr == NULL)
        return;
    
    for (i = 0; i < IWM_NUM_OF_FW_PAGING_BLOCKS; i++) {
        iwm_dma_contig_free(&sc->fw_paging_db[i].fw_paging_block);
    }
    
    memset(sc->fw_paging_db, 0, sizeof(sc->fw_paging_db));
}

int itlwm::
iwm_fill_paging_mem(struct iwm_softc *sc, const struct iwm_fw_sects *image)
{
    int sec_idx, idx;
    uint32_t offset = 0;
    
    /*
     * find where is the paging image start point:
     * if CPU2 exist and it's in paging format, then the image looks like:
     * CPU1 sections (2 or more)
     * CPU1_CPU2_SEPARATOR_SECTION delimiter - separate between CPU1 to CPU2
     * CPU2 sections (not paged)
     * PAGING_SEPARATOR_SECTION delimiter - separate between CPU2
     * non paged to CPU2 paging sec
     * CPU2 paging CSS
     * CPU2 paging image (including instruction and data)
     */
    for (sec_idx = 0; sec_idx < IWM_UCODE_SECT_MAX; sec_idx++) {
        if (image->fw_sect[sec_idx].fws_devoff ==
            IWM_PAGING_SEPARATOR_SECTION) {
            sec_idx++;
            break;
        }
    }
    
    /*
     * If paging is enabled there should be at least 2 more sections left
     * (one for CSS and one for Paging data)
     */
    if (sec_idx >= nitems(image->fw_sect) - 1) {
        XYLog("%s: Paging: Missing CSS and/or paging sections\n",
              DEVNAME(sc));
        iwm_free_fw_paging(sc);
        return EINVAL;
    }
    
    /* copy the CSS block to the dram */
    XYLog("%s: Paging: load paging CSS to FW, sec = %d\n",
          DEVNAME(sc), sec_idx);
    
    memcpy(sc->fw_paging_db[0].fw_paging_block.vaddr,
           image->fw_sect[sec_idx].fws_data,
           sc->fw_paging_db[0].fw_paging_size);
    
    XYLog("%s: Paging: copied %d CSS bytes to first block\n",
          DEVNAME(sc), sc->fw_paging_db[0].fw_paging_size);
    
    sec_idx++;
    
    /*
     * copy the paging blocks to the dram
     * loop index start from 1 since that CSS block already copied to dram
     * and CSS index is 0.
     * loop stop at num_of_paging_blk since that last block is not full.
     */
    for (idx = 1; idx < sc->num_of_paging_blk; idx++) {
        memcpy(sc->fw_paging_db[idx].fw_paging_block.vaddr,
               (const char *)image->fw_sect[sec_idx].fws_data + offset,
               sc->fw_paging_db[idx].fw_paging_size);
        
        XYLog("%s: Paging: copied %d paging bytes to block %d\n",
              DEVNAME(sc), sc->fw_paging_db[idx].fw_paging_size, idx);
        
        offset += sc->fw_paging_db[idx].fw_paging_size;
    }
    
    /* copy the last paging block */
    if (sc->num_of_pages_in_last_blk > 0) {
        memcpy(sc->fw_paging_db[idx].fw_paging_block.vaddr,
               (const char *)image->fw_sect[sec_idx].fws_data + offset,
               IWM_FW_PAGING_SIZE * sc->num_of_pages_in_last_blk);
        
        XYLog("%s: Paging: copied %d pages in the last block %d\n",
              DEVNAME(sc), sc->num_of_pages_in_last_blk, idx);
    }
    
    return 0;
}

int itlwm::
iwm_alloc_fw_paging_mem(struct iwm_softc *sc, const struct iwm_fw_sects *image)
{
    int blk_idx = 0;
    int error, num_of_pages;
    
    if (sc->fw_paging_db[0].fw_paging_block.vaddr != NULL) {
        //        int i;
        //        /* Device got reset, and we setup firmware paging again */
        //        bus_dmamap_sync(sc->sc_dmat,
        //            sc->fw_paging_db[0].fw_paging_block.map,
        //            0, IWM_FW_PAGING_SIZE,
        //            BUS_DMASYNC_POSTWRITE | BUS_DMASYNC_POSTREAD);
        //        for (i = 1; i < sc->num_of_paging_blk + 1; i++) {
        //            bus_dmamap_sync(sc->sc_dmat,
        //                sc->fw_paging_db[i].fw_paging_block.map,
        //                0, IWM_PAGING_BLOCK_SIZE,
        //                BUS_DMASYNC_POSTWRITE | BUS_DMASYNC_POSTREAD);
        //        }
        return 0;
    }
    
    /* ensure IWM_BLOCK_2_EXP_SIZE is power of 2 of IWM_PAGING_BLOCK_SIZE */
#if (1 << IWM_BLOCK_2_EXP_SIZE) != IWM_PAGING_BLOCK_SIZE
#error IWM_BLOCK_2_EXP_SIZE must be power of 2 of IWM_PAGING_BLOCK_SIZE
#endif
    
    num_of_pages = image->paging_mem_size / IWM_FW_PAGING_SIZE;
    sc->num_of_paging_blk =
    ((num_of_pages - 1) / IWM_NUM_OF_PAGE_PER_GROUP) + 1;
    
    sc->num_of_pages_in_last_blk =
    num_of_pages -
    IWM_NUM_OF_PAGE_PER_GROUP * (sc->num_of_paging_blk - 1);
    
    XYLog("%s: Paging: allocating mem for %d paging blocks, each block"
          " holds 8 pages, last block holds %d pages\n", DEVNAME(sc),
          sc->num_of_paging_blk,
          sc->num_of_pages_in_last_blk);
    
    /* allocate block of 4Kbytes for paging CSS */
    error = iwm_dma_contig_alloc(sc->sc_dmat,
                                 &sc->fw_paging_db[blk_idx].fw_paging_block, NULL, IWM_FW_PAGING_SIZE,
                                 4096);
    if (error) {
        /* free all the previous pages since we failed */
        iwm_free_fw_paging(sc);
        return ENOMEM;
    }
    
    sc->fw_paging_db[blk_idx].fw_paging_size = IWM_FW_PAGING_SIZE;
    
    XYLog("%s: Paging: allocated 4K(CSS) bytes for firmware paging.\n",
          DEVNAME(sc));
    
    /*
     * allocate blocks in dram.
     * since that CSS allocated in fw_paging_db[0] loop start from index 1
     */
    for (blk_idx = 1; blk_idx < sc->num_of_paging_blk + 1; blk_idx++) {
        /* allocate block of IWM_PAGING_BLOCK_SIZE (32K) */
        /* XXX Use iwm_dma_contig_alloc for allocating */
        error = iwm_dma_contig_alloc(sc->sc_dmat,
                                     &sc->fw_paging_db[blk_idx].fw_paging_block, NULL,
                                     IWM_PAGING_BLOCK_SIZE, 4096);
        if (error) {
            /* free all the previous pages since we failed */
            iwm_free_fw_paging(sc);
            return ENOMEM;
        }
        
        sc->fw_paging_db[blk_idx].fw_paging_size =
        IWM_PAGING_BLOCK_SIZE;
        
        XYLog(
              "%s: Paging: allocated 32K bytes for firmware paging.\n",
              DEVNAME(sc));
    }
    
    return 0;
}

int itlwm::
iwm_save_fw_paging(struct iwm_softc *sc, const struct iwm_fw_sects *fw)
{
    XYLog("%s\n", __FUNCTION__);
    int ret;
    
    ret = iwm_alloc_fw_paging_mem(sc, fw);
    if (ret)
        return ret;
    
    return iwm_fill_paging_mem(sc, fw);
}

/* send paging cmd to FW in case CPU2 has paging image */
int itlwm::
iwm_send_paging_cmd(struct iwm_softc *sc, const struct iwm_fw_sects *fw)
{
    XYLog("%s\n", __FUNCTION__);
    int blk_idx;
    uint32_t dev_phy_addr;
    struct iwm_fw_paging_cmd fw_paging_cmd = {
        .flags =
        htole32(IWM_PAGING_CMD_IS_SECURED |
                IWM_PAGING_CMD_IS_ENABLED |
                (sc->num_of_pages_in_last_blk <<
                 IWM_PAGING_CMD_NUM_OF_PAGES_IN_LAST_GRP_POS)),
        .block_size = htole32(IWM_BLOCK_2_EXP_SIZE),
        .block_num = htole32(sc->num_of_paging_blk),
    };
    
    /* loop for for all paging blocks + CSS block */
    for (blk_idx = 0; blk_idx < sc->num_of_paging_blk + 1; blk_idx++) {
        dev_phy_addr = htole32(
                               sc->fw_paging_db[blk_idx].fw_paging_block.paddr >>
                               IWM_PAGE_2_EXP_SIZE);
        fw_paging_cmd.device_phy_addr[blk_idx] = dev_phy_addr;
        //        bus_dmamap_sync(sc->sc_dmat,
        //            sc->fw_paging_db[blk_idx].fw_paging_block.map, 0,
        //            blk_idx == 0 ? IWM_FW_PAGING_SIZE : IWM_PAGING_BLOCK_SIZE,
        //            BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
    }
    
    return iwm_send_cmd_pdu(sc, iwm_cmd_id(IWM_FW_PAGING_BLOCK_CMD,
                                           IWM_LONG_GROUP, 0),
                            0, sizeof(fw_paging_cmd), &fw_paging_cmd);
}
