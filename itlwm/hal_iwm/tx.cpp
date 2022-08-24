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

void ItlIwm::
iwm_free_tx_ring(iwm_softc *sc, struct iwm_tx_ring *ring)
{
    int i;
    
    iwm_dma_contig_free(&ring->desc_dma);
    iwm_dma_contig_free(&ring->cmd_dma);
    
    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
}

void ItlIwm::
iwm_reset_tx_ring(struct iwm_softc *sc, struct iwm_tx_ring *ring)
{
    int i;
    
    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];

        if (data->m != NULL) {
//            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
//                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
//            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
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

int ItlIwm::
iwm_alloc_tx_ring(iwm_softc *sc, struct iwm_tx_ring *ring, int qid)
{
    bus_addr_t paddr;
    bus_size_t size;
    int i, err;
    int nsegments;
    
    ring->qid = qid;
    ring->queued = 0;
    ring->cur = 0;
    ring->tail = 0;
    
    /* We are using 10:17 for DQA tx agg */
    if (qid > IWM_LAST_AGG_TX_QUEUE)
        return 0;
    
    /* Allocate TX descriptors (256-byte aligned). */
    size = IWM_TX_RING_COUNT * sizeof (struct iwm_tfd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, size, 256);
    if (err) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    ring->desc = (struct iwm_tfd *)ring->desc_dma.vaddr;
    
    size = IWM_TX_RING_COUNT * sizeof(struct iwm_device_cmd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma, size, 4);
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
        if (qid == IWM_CMD_QUEUE || qid == IWM_DQA_CMD_QUEUE) {
            mapsize = (sizeof(struct iwm_cmd_header) + IWM_MAX_CMD_PAYLOAD_SIZE);
            nsegments = 1;
        } else {
            mapsize = MCLBYTES;
            nsegments = IWM_NUM_OF_TBS - 2;
        }
        err = bus_dmamap_create(sc->sc_dmat, mapsize,
                                nsegments, mapsize, 0, BUS_DMA_NOWAIT,
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

int ItlIwm::
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

int ItlIwm::
iwm_enable_txq(struct iwm_softc *sc, int sta_id, int qid, int fifo, int ssn, int tid, int agg)
{
    XYLog("%s qid=%d tid=%d agg=%d\n", __FUNCTION__, qid, tid, agg);
    struct iwm_scd_txq_cfg_cmd cmd;
    int err = 0;
    uint16_t idx;
    struct iwm_tx_ring *ring = &sc->txq[qid];
    bool scd_bug = false;
    
    if (agg &&
        (sc->agg_queue_mask & (1 << qid)))
        return 0;
    
    iwm_nic_assert_locked(sc);
    
    /*
     * If we need to move the SCD write pointer by steps of
     * 0x40, 0x80 or 0xc0, it gets stuck. Avoids this and let
     * the op_mode know by returning true later.
     * Do this only in case cfg is NULL since this trick can
     * be done only if we have DQA enabled which is true for mvm
     * only. And mvm never sets a cfg pointer.
     * This is really ugly, but this is the easiest way out for
     * this sad hardware issue.
     * This bug has been fixed on devices 9000 and up.
     */
    scd_bug = !sc->sc_mqrx_supported &&
    !((ssn - ring->cur) & 0x3f) &&
    (ssn != ring->cur);
    if (scd_bug)
        ssn = (ssn + 1) & 0xfff;
    
    idx = IWM_AGG_SSN_TO_TXQ_IDX(ssn);
    ring->cur = ring->read = idx;
    ring->tail = idx;
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, (qid << 8) | idx);
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.scd_queue = qid;
    cmd.enable = IWM_SCD_CFG_ENABLE_QUEUE;
    cmd.window = IWM_FRAME_LIMIT;
    cmd.sta_id = sta_id;
    cmd.ssn = htole16(ssn);
    cmd.tx_fifo = fifo;
    cmd.aggregate = agg;
    cmd.tid = tid;

    iwm_write_prph(sc, IWM_SCD_QUEUE_RDPTR(qid), ssn);

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

    err = iwm_send_cmd_pdu(sc, IWM_SCD_QUEUE_CFG, 0,
                           sizeof(cmd), &cmd);
    if (err)
        XYLog("%s failed error=%d\n", __FUNCTION__, err);
    
    return err;
}

int ItlIwm::
iwm_disable_txq(struct iwm_softc *sc, uint8_t qid, uint8_t tid, uint8_t flags)
{
    int err;
    struct iwm_scd_txq_cfg_cmd cmd = {
        .scd_queue = qid,
        .enable = IWM_SCD_CFG_DISABLE_QUEUE,
        .sta_id = IWM_STATION_ID,
        .tid = tid,
    };
    
    err = iwm_send_cmd_pdu(sc, IWM_SCD_QUEUE_CFG, flags,
                               sizeof(struct iwm_scd_txq_cfg_cmd), &cmd);
    return err;
}

int ItlIwm::
iwm_send_soc_conf(struct iwm_softc *sc)
{
    struct iwm_soc_configuration_cmd cmd;
    int err;
    uint32_t cmd_id, flags = 0;
    
    memset(&cmd, 0, sizeof(cmd));
    
    /*
     * In VER_1 of this command, the discrete value is considered
     * an integer; In VER_2, it's a bitmask.  Since we have only 2
     * values in VER_1, this is backwards-compatible with VER_2,
     * as long as we don't set any other flag bits.
     */
    if (!sc->sc_integrated) { /* VER_1 */
        flags = IWM_SOC_CONFIG_CMD_FLAGS_DISCRETE;
    } else { /* VER_2 */
        uint8_t scan_cmd_ver;
        if (sc->sc_ltr_delay != IWM_SOC_FLAGS_LTR_APPLY_DELAY_NONE)
            flags |= (sc->sc_ltr_delay &
                      IWM_SOC_FLAGS_LTR_APPLY_DELAY_MASK);
        scan_cmd_ver = iwm_lookup_cmd_ver(sc, IWM_LONG_GROUP,
                                          IWM_SCAN_REQ_UMAC);
        if (scan_cmd_ver != IWM_FW_CMD_VER_UNKNOWN &&
            scan_cmd_ver >= 2 && sc->sc_low_latency_xtal)
            flags |= IWM_SOC_CONFIG_CMD_FLAGS_LOW_LATENCY;
    }
    cmd.flags = htole32(flags);
    
    cmd.latency = htole32(sc->sc_xtal_latency);
    
    cmd_id = iwm_cmd_id(IWM_SOC_CONFIGURATION_CMD, IWM_SYSTEM_GROUP, 0);
    err = iwm_send_cmd_pdu(sc, cmd_id, 0, sizeof(cmd), &cmd);
    if (err)
        printf("%s: failed to set soc latency: %d\n", DEVNAME(sc), err);
    return err;
}

int ItlIwm::
iwm_send_update_mcc_cmd(struct iwm_softc *sc, const char *alpha2)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_mcc_update_cmd mcc_cmd;
    struct iwm_host_cmd hcmd = {
        .id = IWM_MCC_UPDATE_CMD,
        .flags = IWM_CMD_WANT_RESP,
        .resp_pkt_len = IWM_CMD_RESP_MAX,
        .data = { &mcc_cmd },
    };
    struct iwm_rx_packet *pkt;
    size_t resp_len;
    int err;
    int resp_v3 = isset(sc->sc_enabled_capa,
                        IWM_UCODE_TLV_CAPA_LAR_SUPPORT_V3);
    
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
    
    if (resp_v3) { /* same size as resp_v2 */
        hcmd.len[0] = sizeof(struct iwm_mcc_update_cmd);
    } else {
        hcmd.len[0] = sizeof(struct iwm_mcc_update_cmd_v1);
    }
    
    err = iwm_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.flags & IWM_CMD_FAILED_MSK)) {
        err = EIO;
        goto out;
    }
    
    if (resp_v3) {
        struct iwm_mcc_update_resp_v3 *resp;
        resp_len = iwm_rx_packet_payload_len(pkt);
        if (resp_len < sizeof(*resp)) {
            err = EIO;
            goto out;
        }
        
        resp = (struct iwm_mcc_update_resp_v3 *)pkt->data;
        if (resp_len != sizeof(*resp) +
            resp->n_channels * sizeof(resp->channels[0])) {
            err = EIO;
            goto out;
        }
    } else {
        struct iwm_mcc_update_resp_v1 *resp_v1;
        resp_len = iwm_rx_packet_payload_len(pkt);
        if (resp_len < sizeof(*resp_v1)) {
            err = EIO;
            goto out;
        }
        
        resp_v1 = (struct iwm_mcc_update_resp_v1 *)pkt->data;
        if (resp_len != sizeof(*resp_v1) +
            resp_v1->n_channels * sizeof(resp_v1->channels[0])) {
            err = EIO;
            goto out;
        }
    }
out:
    iwm_free_resp(sc, &hcmd);
    return err;
}

int ItlIwm::
iwm_send_temp_report_ths_cmd(struct iwm_softc *sc)
{
    struct iwm_temp_report_ths_cmd cmd;
    int err;
    
    /*
     * In order to give responsibility for critical-temperature-kill
     * and TX backoff to FW we need to send an empty temperature
     * reporting command at init time.
     */
    memset(&cmd, 0, sizeof(cmd));
    
    err = iwm_send_cmd_pdu(sc,
                           IWM_WIDE_ID(IWM_PHY_OPS_GROUP, IWM_TEMP_REPORTING_THRESHOLDS_CMD),
                           0, sizeof(cmd), &cmd);
    if (err)
        printf("%s: TEMP_REPORT_THS_CMD command failed (error %d)\n",
               DEVNAME(sc), err);
    
    return err;
}

void ItlIwm::
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

void ItlIwm::
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

int ItlIwm::
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

int ItlIwm::
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
        &sc->fw_paging_db[blk_idx].fw_paging_block, IWM_FW_PAGING_SIZE,
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
             &sc->fw_paging_db[blk_idx].fw_paging_block,
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

int ItlIwm::
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
int ItlIwm::
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
