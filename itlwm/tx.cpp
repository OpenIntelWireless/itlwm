//
//  tx.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

void itlwm::
iwm_free_tx_ring(iwm_softc *sc, struct iwm_tx_ring *ring)
{
    int i;

    iwm_dma_contig_free(&ring->desc_dma);
    iwm_dma_contig_free(&ring->cmd_dma);

    for (i = 0; i < IWM_TX_RING_COUNT; i++) {
        struct iwm_tx_data *data = &ring->data[i];

        if (data->m != NULL) {
            mbuf_freem(data->m);
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
    if (ring->qid == IWM_CMD_QUEUE && ring->queued > 0) {
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
            iwm_nic_unlock(sc);
    }
    ring->queued = 0;
    ring->cur = 0;
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

    /* Allocate TX descriptors (256-byte aligned). */
    size = IWM_TX_RING_COUNT * sizeof (struct iwm_tfd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, (void **)&ring->desc, size, 256);
    if (err) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
            "AppleIntel");
        goto fail;
    }
    ring->desc = (struct iwm_tfd *)ring->desc_dma.vaddr;

    /*
     * We only use rings 0 through 9 (4 EDCA + cmd) so there is no need
     * to allocate commands space for other rings.
     */
    if (qid > IWM_CMD_QUEUE)
        return 0;

    size = IWM_TX_RING_COUNT * sizeof(struct iwm_device_cmd);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma, (void **)&ring->cmd, size, 4);
    if (err) {
        XYLog("%s: could not allocate cmd DMA memory\n", "AppleIntel");
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
        if (qid == IWM_CMD_QUEUE)
            mapsize = (sizeof(struct iwm_cmd_header) +
                IWM_MAX_CMD_PAYLOAD_SIZE);
        else
            mapsize = MCLBYTES;
        err = bus_dmamap_create(sc->sc_dmat, mapsize,
            IWM_NUM_OF_TBS - 2, mapsize, 0, BUS_DMA_NOWAIT,
            &data->map);
        if (err) {
            XYLog("%s: could not create TX buf DMA map\n",
                "AppleIntel");
            goto fail;
        }
    }
    return 0;

fail:
    iwm_free_tx_ring(sc, ring);
    return err;
}

int itlwm::
iwm_enable_txq(struct iwm_softc *sc, int sta_id, int qid, int fifo)
{
    XYLog("%s\n", __func__);
    iwm_nic_assert_locked(sc);

    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, qid << 8 | 0);

    if (qid == IWM_CMD_QUEUE) {
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
    } else {
        struct iwm_scd_txq_cfg_cmd cmd;
        int err;

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
    }

    iwm_write_prph(sc, IWM_SCD_EN_CTRL,
        iwm_read_prph(sc, IWM_SCD_EN_CTRL) | qid);

    return 0;
}

int itlwm::
iwm_send_update_mcc_cmd(struct iwm_softc *sc, const char *alpha2)
{
    XYLog("%s\n", __func__);
    struct iwm_mcc_update_cmd mcc_cmd;
    struct iwm_host_cmd hcmd = {
        .id = IWM_MCC_UPDATE_CMD,
        .flags = IWM_CMD_WANT_RESP,
        .data = { &mcc_cmd },
    };
    int err;
    int resp_v2 = isset(sc->sc_enabled_capa,
        IWM_UCODE_TLV_CAPA_LAR_SUPPORT_V2);

    memset(&mcc_cmd, 0, sizeof(mcc_cmd));
    mcc_cmd.mcc = htole16(alpha2[0] << 8 | alpha2[1]);
    if ((sc->sc_ucode_api & IWM_UCODE_TLV_API_WIFI_MCC_UPDATE) ||
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
    XYLog("%s\n", __func__);
    struct iwm_host_cmd cmd = {
        .id = IWM_REPLY_THERMAL_MNG_BACKOFF,
        .len = { sizeof(uint32_t), },
        .data = { &backoff, },
    };

    iwm_send_cmd(sc, &cmd);
}
