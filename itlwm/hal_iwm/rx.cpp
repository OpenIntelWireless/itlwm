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
#include <net80211/ieee80211_priv.h>

void ItlIwm::
iwm_disable_rx_dma(struct iwm_softc *sc)
{
    int ntries;
    
    if (iwm_nic_lock(sc)) {
        if (sc->sc_mqrx_supported) {
            iwm_write_prph(sc, IWM_RFH_RXF_DMA_CFG, 0);
            for (ntries = 0; ntries < 1000; ntries++) {
                if (iwm_read_prph(sc, IWM_RFH_GEN_STATUS) &
                    IWM_RXF_DMA_IDLE)
                    break;
                DELAY(10);
            }
        } else {
            IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
            for (ntries = 0; ntries < 1000; ntries++) {
                if (IWM_READ(sc, IWM_FH_MEM_RSSR_RX_STATUS_REG)&
                    IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE)
                    break;
                DELAY(10);
            }
        }
        iwm_nic_unlock(sc);
    }
}

void ItlIwm::
iwm_reset_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    ring->cur = 0;
    //    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
    //        ring->stat_dma.size, BUS_DMASYNC_PREWRITE);
    memset(ring->stat, 0, sizeof(*ring->stat));
    //    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
    //        ring->stat_dma.size, BUS_DMASYNC_POSTWRITE);
    
}

void ItlIwm::
iwm_free_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    int count, i;
    
    iwm_dma_contig_free(&ring->free_desc_dma);
    iwm_dma_contig_free(&ring->stat_dma);
    iwm_dma_contig_free(&ring->used_desc_dma);
    
    if (sc->sc_mqrx_supported)
        count = IWM_RX_MQ_RING_COUNT;
    else
        count = IWM_RX_RING_COUNT;
    
    for (i = 0; i < count; i++) {
        struct iwm_rx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
            //                data->map->dm_mapsize, BUS_DMASYNC_POSTREAD);
            //            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
}

int ItlIwm::
iwm_alloc_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    bus_size_t size;
    size_t descsz;
    int count, i, err;
    
    ring->cur = 0;
    
    if (sc->sc_mqrx_supported) {
        count = IWM_RX_MQ_RING_COUNT;
        descsz = sizeof(uint64_t);
    } else {
        count = IWM_RX_RING_COUNT;
        descsz = sizeof(uint32_t);
    }
    
    /* Allocate RX descriptors (256-byte aligned). */
    size = count * descsz;
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->free_desc_dma, size, 256);
    if (err) {
        XYLog("%s: could not allocate RX ring DMA memory\n",
            DEVNAME(sc));
        goto fail;
    }
    ring->desc = ring->free_desc_dma.vaddr;

    /* Allocate RX status area (16-byte aligned). */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->stat_dma,
        sizeof(*ring->stat), 16);
    if (err) {
        XYLog("%s: could not allocate RX status DMA memory\n",
            DEVNAME(sc));
        goto fail;
    }
    ring->stat = (struct iwm_rb_status *)ring->stat_dma.vaddr;

    if (sc->sc_mqrx_supported) {
        size = count * sizeof(uint32_t);
        err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->used_desc_dma,
            size, 256);
        if (err) {
            XYLog("%s: could not allocate RX ring DMA memory\n",
                DEVNAME(sc));
            goto fail;
        }
    }
    
    for (i = 0; i < count; i++) {
        struct iwm_rx_data *data = &ring->data[i];
        
        memset(data, 0, sizeof(*data));
        err = bus_dmamap_create(sc->sc_dmat, IWM_RBUF_SIZE, 1,
                                IWM_RBUF_SIZE, 0, BUS_DMA_NOWAIT,
                                &data->map);
        if (err) {
            XYLog("%s: could not create RX buf DMA map\n",
                  DEVNAME(sc));
            goto fail;
        }
        
        err = iwm_rx_addbuf(sc, IWM_RBUF_SIZE, i);
        if (err)
            goto fail;
    }
    return 0;
    
fail:    iwm_free_rx_ring(sc, ring);
    return err;
}

int ItlIwm::
iwm_rx_addbuf(struct iwm_softc *sc, int size, int idx)
{
    struct iwm_rx_ring *ring = &sc->rxq;
    struct iwm_rx_data *data = &ring->data[idx];
    mbuf_t m;
    int err;
    int fatal = 0;
    unsigned int maxChunks = 1;
    IOPhysicalSegment seg;
    
//    mbuf_allocpacket(MBUF_WAITOK, size, NULL, &m);
    
    m = getController()->allocatePacket(size);
//
    if (m == NULL) {
        XYLog("%s allocatePacket==NULL\n", __FUNCTION__);
        return ENOMEM;
    }
//        mbuf_gethdr(MBUF_DONTWAIT, MT_DATA, &m);
//        if (m == NULL)
//            return ENOBUFS;
//
//        if (size <= MCLBYTES) {
//            mbuf_mclget(MBUF_DONTWAIT, MT_DATA, &m);
//        } else {
//            mbuf_getcluster(MBUF_DONTWAIT, MT_DATA, IWM_RBUF_SIZE, &m);
//        }
//        if ((mbuf_flags(m) & MBUF_EXT) == 0) {
//            mbuf_freem(m);
//            return ENOBUFS;
//        }
//
//        if (data->m != NULL) {
//    //        bus_dmamap_unload(sc->sc_dmat, data->map);
//            fatal = 1;
//        }
    
//        mbuf_setlen(m, size);
//        mbuf_pkthdr_setlen(m, size);
    //    m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;
//    err = bus_dmamap_load(data->map, m);
    data->map->dm_nsegs = data->map->cursor->getPhysicalSegments(m, &seg, 1);
//    XYLog("map rx dm_nsegs=%d\n", data->map->dm_nsegs);
    if (data->map->dm_nsegs == 0) {
        XYLog("RX Map new address FAIL!!!!\n");
        /* XXX */
        if (fatal)
            panic("iwm: could not load RX mbuf");
        mbuf_freem(m);
        return ENOMEM;
    }
    data->m = m;
    //    bus_dmamap_sync(sc->sc_dmat, data->map, 0, size, BUS_DMASYNC_PREREAD);
    
    /* Update RX descriptor. */
    if (sc->sc_mqrx_supported) {
        ((uint64_t *)ring->desc)[idx] =
        htole64(seg.location);
        //        bus_dmamap_sync(sc->sc_dmat, ring->free_desc_dma.map,
        //            idx * sizeof(uint64_t), sizeof(uint64_t),
        //            BUS_DMASYNC_PREWRITE);
    } else {
        ((uint32_t *)ring->desc)[idx] =
        htole32(seg.location >> 8);
        //        bus_dmamap_sync(sc->sc_dmat, ring->free_desc_dma.map,
        //            idx * sizeof(uint32_t), sizeof(uint32_t),
        //            BUS_DMASYNC_PREWRITE);
    }
    
    return 0;
}

void ItlIwm::
iwm_rx_rx_phy_cmd(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
                  struct iwm_rx_data *data)
{
    struct iwm_rx_phy_info *phy_info = (struct iwm_rx_phy_info *)pkt->data;
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
    //        sizeof(*phy_info), BUS_DMASYNC_POSTREAD);
    
    memcpy(&sc->sc_last_phy_info, phy_info, sizeof(sc->sc_last_phy_info));
}

void ItlIwm::
iwm_rx_mpdu(struct iwm_softc *sc, mbuf_t m, void *pktdata,
            size_t maxlen, struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_rxinfo rxi;
    struct ieee80211_rx_status rx_status;
    struct iwm_rx_phy_info *phy_info;
    struct iwm_rx_mpdu_res_start *rx_res;
    int device_timestamp;
    uint16_t phy_flags;
    uint32_t len;
    uint32_t rx_pkt_status;
    int rssi, chanidx, rate_n_flags;
    
    memset(&rxi, 0, sizeof(rxi));
    memset(&rx_status, 0, sizeof(struct ieee80211_rx_status));
    
    phy_info = &sc->sc_last_phy_info;
    rx_res = (struct iwm_rx_mpdu_res_start *)pktdata;
    len = le16toh(rx_res->byte_count);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Allow control frames in monitor mode. */
        if (len < sizeof(struct ieee80211_frame_cts)) {
            ic->ic_stats.is_rx_tooshort++;
            IC2IFP(ic)->netStat->inputErrors++;
            mbuf_freem(m);
            return;
        }
    } else if (len < sizeof(struct ieee80211_frame)) {
        ic->ic_stats.is_rx_tooshort++;
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    if (len > maxlen - sizeof(*rx_res)) {
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    
    if (phy_info->cfg_phy_cnt > 20) {
        mbuf_freem(m);
        return;
    }
    
    rx_pkt_status = le32toh(*(uint32_t *)((uint8_t*)pktdata + sizeof(*rx_res) + len));
    if (!(rx_pkt_status & IWM_RX_MPDU_RES_STATUS_CRC_OK) ||
        !(rx_pkt_status & IWM_RX_MPDU_RES_STATUS_OVERRUN_OK)) {
        mbuf_freem(m);
        return; /* drop */
    }
    
    //    m->m_data = pktdata + sizeof(*rx_res);
    //    m->m_pkthdr.len = m->m_len = len;
    mbuf_setdata(m, ((uint8_t*)pktdata + sizeof(*rx_res)), len);
    mbuf_pkthdr_setlen(m, len);
    mbuf_setlen(m, len);
    
    if (iwm_rx_hwdecrypt(sc, m, rx_pkt_status, &rxi)) {
        mbuf_freem(m);
        return;
    }
    
    chanidx = letoh32(phy_info->channel);
    device_timestamp = le32toh(phy_info->system_timestamp);
    phy_flags = letoh16(phy_info->phy_flags);
    rate_n_flags = le32toh(phy_info->rate_n_flags);

    rssi = iwm_get_signal_strength(sc, &rx_status, phy_info);
    rs_update_last_rssi(sc, &rx_status);
    rssi = (0 - IWM_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */

    rxi.rxi_rssi = rssi;
    rxi.rxi_tstamp = device_timestamp;
    rxi.rxi_chan = chanidx;
    
    iwm_rx_frame(sc, m, chanidx, rx_pkt_status,
                 (phy_flags & IWM_PHY_INFO_FLAG_SHPREAMBLE),
                 rate_n_flags, device_timestamp, &rxi, ml);
}

void ItlIwm::
iwm_flip_address(uint8_t *addr)
{
    int i;
    uint8_t mac_addr[ETHER_ADDR_LEN];
    
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        mac_addr[i] = addr[ETHER_ADDR_LEN - i - 1];
    IEEE80211_ADDR_COPY(addr, mac_addr);
}

/*
 * Drop duplicate 802.11 retransmissions
 * (IEEE 802.11-2012: 9.3.2.10 "Duplicate detection and recovery")
 * and handle pseudo-duplicate frames which result from deaggregation
 * of A-MSDU frames in hardware.
 */
int ItlIwm::
iwm_detect_duplicate(struct iwm_softc *sc, mbuf_t m,
                     struct iwm_rx_mpdu_desc *desc, struct ieee80211_rxinfo *rxi)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    struct iwm_rxq_dup_data *dup_data = &in->dup_data;
    uint8_t tid = IWM_MAX_TID_COUNT, subframe_idx;
    struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
    uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    int hasqos = ieee80211_has_qos(wh);
    uint16_t seq;
    
    if (type == IEEE80211_FC0_TYPE_CTL ||
        (hasqos && (subtype & IEEE80211_FC0_SUBTYPE_NODATA)) ||
        IEEE80211_IS_MULTICAST(wh->i_addr1))
        return 0;
    
    if (hasqos) {
        tid = (ieee80211_get_qos(wh) & IEEE80211_QOS_TID);
        if (tid > IWM_MAX_TID_COUNT)
            tid = IWM_MAX_TID_COUNT;
    }
    
    /* If this wasn't a part of an A-MSDU the sub-frame index will be 0 */
    subframe_idx = desc->amsdu_info &
    IWM_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK;
    
    seq = letoh16(*(u_int16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
    if ((wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
        dup_data->last_seq[tid] == seq &&
        dup_data->last_sub_frame[tid] >= subframe_idx)
        return 1;
    
    /*
     * Allow the same frame sequence number for all A-MSDU subframes
     * following the first subframe.
     * Otherwise these subframes would be discarded as replays.
     */
    if (dup_data->last_seq[tid] == seq &&
        subframe_idx > dup_data->last_sub_frame[tid] &&
        (desc->mac_flags2 & IWM_RX_MPDU_MFLG2_AMSDU)) {
        rxi->rxi_flags |= IEEE80211_RXI_SAME_SEQ;
    }
    
    dup_data->last_seq[tid] = seq;
    dup_data->last_sub_frame[tid] = subframe_idx;
    
    return 0;
}

/*
 * Returns true if sn2 - buffer_size < sn1 < sn2.
 * To be used only in order to compare reorder buffer head with NSSN.
 * We fully trust NSSN unless it is behind us due to reorder timeout.
 * Reorder timeout can only bring us up to buffer_size SNs ahead of NSSN.
 */
int ItlIwm::
iwm_is_sn_less(uint16_t sn1, uint16_t sn2, uint16_t buffer_size)
{
    return SEQ_LT(sn1, sn2) && !SEQ_LT(sn1, sn2 - buffer_size);
}

void ItlIwm::
iwm_release_frames(struct iwm_softc *sc, struct ieee80211_node *ni,
                   struct iwm_rxba_data *rxba, struct iwm_reorder_buffer *reorder_buf,
                   uint16_t nssn, struct mbuf_list *ml)
{
    struct iwm_reorder_buf_entry *entries = &rxba->entries[0];
    uint16_t ssn = reorder_buf->head_sn;
    
    /* ignore nssn smaller than head sn - this can happen due to timeout */
    if (iwm_is_sn_less(nssn, ssn, reorder_buf->buf_size))
        goto set_timer;
    
    while (iwm_is_sn_less(ssn, nssn, reorder_buf->buf_size)) {
        int index = ssn % reorder_buf->buf_size;
        mbuf_t m;
        int chanidx, is_shortpre;
        uint32_t rx_pkt_status, rate_n_flags, device_timestamp;
        struct ieee80211_rxinfo *rxi;
        
        /* This data is the same for all A-MSDU subframes. */
        chanidx = entries[index].chanidx;
        rx_pkt_status = entries[index].rx_pkt_status;
        is_shortpre = entries[index].is_shortpre;
        rate_n_flags = entries[index].rate_n_flags;
        device_timestamp = entries[index].device_timestamp;
        rxi = &entries[index].rxi;
        
        /*
         * Empty the list. Will have more than one frame for A-MSDU.
         * Empty list is valid as well since nssn indicates frames were
         * received.
         */
        while ((m = ml_dequeue(&entries[index].frames)) != NULL) {
            iwm_rx_frame(sc, m, chanidx, rx_pkt_status, is_shortpre,
                         rate_n_flags, device_timestamp, rxi, ml);
            reorder_buf->num_stored--;
            
            /*
             * Allow the same frame sequence number and CCMP PN for
             * all A-MSDU subframes following the first subframe.
             * Otherwise they would be discarded as replays.
             */
            rxi->rxi_flags |= IEEE80211_RXI_SAME_SEQ;
            rxi->rxi_flags |= IEEE80211_RXI_HWDEC_SAME_PN;
        }
        
        ssn = (ssn + 1) & 0xfff;
    }
    reorder_buf->head_sn = nssn;
    
set_timer:
    if (reorder_buf->num_stored && !reorder_buf->removed) {
        timeout_add_usec(&reorder_buf->reorder_timer,
                         RX_REORDER_BUF_TIMEOUT_MQ_USEC);
    } else
        timeout_del(&reorder_buf->reorder_timer);
}

int ItlIwm::
iwm_oldsn_workaround(struct iwm_softc *sc, struct ieee80211_node *ni, int tid,
                     struct iwm_reorder_buffer *buffer, uint32_t reorder_data, uint32_t gp2)
{
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (gp2 != buffer->consec_oldsn_ampdu_gp2) {
        /* we have a new (A-)MPDU ... */
        
        /*
         * reset counter to 0 if we didn't have any oldsn in
         * the last A-MPDU (as detected by GP2 being identical)
         */
        if (!buffer->consec_oldsn_prev_drop)
            buffer->consec_oldsn_drops = 0;
        
        /* either way, update our tracking state */
        buffer->consec_oldsn_ampdu_gp2 = gp2;
    } else if (buffer->consec_oldsn_prev_drop) {
        /*
         * tracking state didn't change, and we had an old SN
         * indication before - do nothing in this case, we
         * already noted this one down and are waiting for the
         * next A-MPDU (by GP2)
         */
        return 0;
    }
    
    /* return unless this MPDU has old SN */
    if (!(reorder_data & IWM_RX_MPDU_REORDER_BA_OLD_SN))
        return 0;
    
    /* update state */
    buffer->consec_oldsn_prev_drop = 1;
    buffer->consec_oldsn_drops++;
    
    /* if limit is reached, send del BA and reset state */
    if (buffer->consec_oldsn_drops == IWM_AMPDU_CONSEC_DROPS_DELBA) {
        XYLog("reached %d old SN frames, stopping BA session on TID %d\n",
              IWM_AMPDU_CONSEC_DROPS_DELBA, tid);
        ieee80211_delba_request(ic, ni, IEEE80211_REASON_UNSPECIFIED,
                                0, tid);
        buffer->consec_oldsn_prev_drop = 0;
        buffer->consec_oldsn_drops = 0;
        return 1;
    }
    
    return 0;
}

/*
 * Handle re-ordering of frames which were de-aggregated in hardware.
 * Returns 1 if the MPDU was consumed (buffered or dropped).
 * Returns 0 if the MPDU should be passed to upper layer.
 */
int ItlIwm::
iwm_rx_reorder(struct iwm_softc *sc, mbuf_t m, int chanidx,
               struct iwm_rx_mpdu_desc *desc, int is_shortpre, int rate_n_flags,
               uint32_t device_timestamp, struct ieee80211_rxinfo *rxi,
               struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni;
    struct iwm_rxba_data *rxba;
    struct iwm_reorder_buffer *buffer;
    uint32_t reorder_data = le32toh(desc->reorder_data);
    int is_amsdu = (desc->mac_flags2 & IWM_RX_MPDU_MFLG2_AMSDU);
    int last_subframe =
    (desc->amsdu_info & IWM_RX_MPDU_AMSDU_LAST_SUBFRAME);
    uint8_t tid;
    uint8_t subframe_idx = (desc->amsdu_info &
                            IWM_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK);
    struct iwm_reorder_buf_entry *entries;
    int index;
    uint16_t nssn, sn;
    uint8_t baid, type, subtype;
    int hasqos;
    
    wh = mtod(m, struct ieee80211_frame *);
    hasqos = ieee80211_has_qos(wh);
    tid = hasqos ? ieee80211_get_qos(wh) & IEEE80211_QOS_TID : 0;
    
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    
    /*
     * We are only interested in Block Ack requests and unicast QoS data.
     */
    if (IEEE80211_IS_MULTICAST(wh->i_addr1))
        return 0;
    if (hasqos) {
        if (subtype & IEEE80211_FC0_SUBTYPE_NODATA)
            return 0;
    } else {
        if (type != IEEE80211_FC0_TYPE_CTL ||
            subtype != IEEE80211_FC0_SUBTYPE_BAR)
            return 0;
    }
    
    baid = (reorder_data & IWM_RX_MPDU_REORDER_BAID_MASK) >>
    IWM_RX_MPDU_REORDER_BAID_SHIFT;
    if (baid == IWM_RX_REORDER_DATA_INVALID_BAID ||
        baid >= nitems(sc->sc_rxba_data))
        return 0;
    
    rxba = &sc->sc_rxba_data[baid];
    if (rxba->reorder_buf.buf_size == 0 || tid != rxba->tid || rxba->sta_id != IWM_STATION_ID)
        return 0;
    
    if (rxba->timeout != 0)
        getmicrouptime(&rxba->last_rx);
    
    /* Bypass A-MPDU re-ordering in net80211. */
    rxi->rxi_flags |= IEEE80211_RXI_AMPDU_DONE;
    
    nssn = reorder_data & IWM_RX_MPDU_REORDER_NSSN_MASK;
    sn = (reorder_data & IWM_RX_MPDU_REORDER_SN_MASK) >>
    IWM_RX_MPDU_REORDER_SN_SHIFT;
    
    buffer = &rxba->reorder_buf;
    entries = &rxba->entries[0];
    
    if (!buffer->valid) {
        if (reorder_data & IWM_RX_MPDU_REORDER_BA_OLD_SN)
            return 0;
        buffer->valid = 1;
    }
    
    ni = ieee80211_find_rxnode(ic, wh);
    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR) {
        iwm_release_frames(sc, ni, rxba, buffer, nssn, ml);
        goto drop;
    }
    
    /*
     * If there was a significant jump in the nssn - adjust.
     * If the SN is smaller than the NSSN it might need to first go into
     * the reorder buffer, in which case we just release up to it and the
     * rest of the function will take care of storing it and releasing up to
     * the nssn.
     */
    if (!iwm_is_sn_less(nssn, buffer->head_sn + buffer->buf_size,
                        buffer->buf_size) ||
        !SEQ_LT(sn, buffer->head_sn + buffer->buf_size)) {
        uint16_t min_sn = SEQ_LT(sn, nssn) ? sn : nssn;
        ic->ic_stats.is_ht_rx_frame_above_ba_winend++;
        iwm_release_frames(sc, ni, rxba, buffer, min_sn, ml);
    }
    
    if (iwm_oldsn_workaround(sc, ni, tid, buffer, reorder_data,
                             device_timestamp)) {
        /* BA session will be torn down. */
        ic->ic_stats.is_ht_rx_ba_window_jump++;
        goto drop;
        
    }
    
    /* drop any outdated packets */
    if (SEQ_LT(sn, buffer->head_sn)) {
        ic->ic_stats.is_ht_rx_frame_below_ba_winstart++;
        goto drop;
    }
    
    /* release immediately if allowed by nssn and no stored frames */
    if (!buffer->num_stored && SEQ_LT(sn, nssn)) {
        if (iwm_is_sn_less(buffer->head_sn, nssn, buffer->buf_size) &&
            (!is_amsdu || last_subframe))
            buffer->head_sn = nssn;
        ieee80211_release_node(ic, ni);
        return 0;
    }
    
    /*
     * release immediately if there are no stored frames, and the sn is
     * equal to the head.
     * This can happen due to reorder timer, where NSSN is behind head_sn.
     * When we released everything, and we got the next frame in the
     * sequence, according to the NSSN we can't release immediately,
     * while technically there is no hole and we can move forward.
     */
    if (!buffer->num_stored && sn == buffer->head_sn) {
        if (!is_amsdu || last_subframe)
            buffer->head_sn = (buffer->head_sn + 1) & 0xfff;
        ieee80211_release_node(ic, ni);
        return 0;
    }
    
    index = sn % buffer->buf_size;
    
    /*
     * Check if we already stored this frame
     * As AMSDU is either received or not as whole, logic is simple:
     * If we have frames in that position in the buffer and the last frame
     * originated from AMSDU had a different SN then it is a retransmission.
     * If it is the same SN then if the subframe index is incrementing it
     * is the same AMSDU - otherwise it is a retransmission.
     */
    if (!ml_empty(&entries[index].frames)) {
        if (!is_amsdu) {
            ic->ic_stats.is_ht_rx_ba_no_buf++;
            goto drop;
        } else if (sn != buffer->last_amsdu ||
                   buffer->last_sub_index >= subframe_idx) {
            ic->ic_stats.is_ht_rx_ba_no_buf++;
            goto drop;
        }
    } else {
        /* This data is the same for all A-MSDU subframes. */
        entries[index].chanidx = chanidx;
        entries[index].is_shortpre = is_shortpre;
        entries[index].rate_n_flags = rate_n_flags;
        entries[index].device_timestamp = device_timestamp;
        memcpy(&entries[index].rxi, rxi, sizeof(entries[index].rxi));
    }
    
    /* put in reorder buffer */
    ml_enqueue(&entries[index].frames, m);
    buffer->num_stored++;
    getmicrouptime(&entries[index].reorder_time);
    
    if (is_amsdu) {
        buffer->last_amsdu = sn;
        buffer->last_sub_index = subframe_idx;
    }
    
    /*
     * We cannot trust NSSN for AMSDU sub-frames that are not the last.
     * The reason is that NSSN advances on the first sub-frame, and may
     * cause the reorder buffer to advance before all the sub-frames arrive.
     * Example: reorder buffer contains SN 0 & 2, and we receive AMSDU with
     * SN 1. NSSN for first sub frame will be 3 with the result of driver
     * releasing SN 0,1, 2. When sub-frame 1 arrives - reorder buffer is
     * already ahead and it will be dropped.
     * If the last sub-frame is not on this queue - we will get frame
     * release notification with up to date NSSN.
     */
    if (!is_amsdu || last_subframe)
        iwm_release_frames(sc, ni, rxba, buffer, nssn, ml);
    
    ieee80211_release_node(ic, ni);
    return 1;
    
drop:
    mbuf_freem(m);
    ieee80211_release_node(ic, ni);
    return 1;
}

void ItlIwm::
iwm_rx_mpdu_mq(struct iwm_softc *sc, mbuf_t m, void *pktdata,
               size_t maxlen, struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_rxinfo rxi;
    struct ieee80211_rx_status rx_status;
    struct iwm_rx_mpdu_desc *desc;
    uint32_t len, hdrlen, rate_n_flags, device_timestamp;
    int rssi;
    uint8_t chanidx;
    uint16_t phy_info;
    
    memset(&rxi, 0, sizeof(rxi));
    memset(&rx_status, 0, sizeof(struct ieee80211_rx_status));
    
    desc = (struct iwm_rx_mpdu_desc *)pktdata;
    
    if (!(desc->status & htole16(IWM_RX_MPDU_RES_STATUS_CRC_OK)) ||
        !(desc->status & htole16(IWM_RX_MPDU_RES_STATUS_OVERRUN_OK))) {
        mbuf_freem(m);
        return; /* drop */
    }
    
    len = le16toh(desc->mpdu_len);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Allow control frames in monitor mode. */
        if (len < sizeof(struct ieee80211_frame_cts)) {
            ic->ic_stats.is_rx_tooshort++;
            IC2IFP(ic)->netStat->inputErrors++;
            mbuf_freem(m);
            return;
        }
    } else if (len < sizeof(struct ieee80211_frame)) {
        ic->ic_stats.is_rx_tooshort++;
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    if (len > maxlen - sizeof(*desc)) {
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    
    //    m->m_data = pktdata + sizeof(*desc);
    //    m->m_pkthdr.len = m->m_len = len;
    mbuf_setdata(m, (uint8_t*)pktdata + sizeof(*desc), len);
    mbuf_pkthdr_setlen(m, len);
    mbuf_setlen(m, len);
    
    /* Account for padding following the frame header. */
    if (desc->mac_flags2 & IWM_RX_MPDU_MFLG2_PAD) {
        struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
        int type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        if (type == IEEE80211_FC0_TYPE_CTL) {
            switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
                case IEEE80211_FC0_SUBTYPE_CTS:
                    hdrlen = sizeof(struct ieee80211_frame_cts);
                    break;
                case IEEE80211_FC0_SUBTYPE_ACK:
                    hdrlen = sizeof(struct ieee80211_frame_ack);
                    break;
                default:
                    hdrlen = sizeof(struct ieee80211_frame_min);
                    break;
            }
        } else
            hdrlen = ieee80211_get_hdrlen(wh);
        
        if ((le16toh(desc->status) &
             IWM_RX_MPDU_RES_STATUS_SEC_ENC_MSK) ==
            IWM_RX_MPDU_RES_STATUS_SEC_CCM_ENC) {
            /* Padding is inserted after the IV. */
            hdrlen += IEEE80211_CCMP_HDRLEN;
        }
        
        memmove((uint8_t*)mbuf_data(m) + 2, mbuf_data(m), hdrlen);
        mbuf_adj(m, 2);
    }
    
    /*
     * Hardware de-aggregates A-MSDUs and copies the same MAC header
     * in place for each subframe. But it leaves the 'A-MSDU present'
     * bit set in the frame header. We need to clear this bit ourselves.
     *
     * And we must allow the same CCMP PN for subframes following the
     * first subframe. Otherwise they would be discarded as replays.
     */
    if (desc->mac_flags2 & IWM_RX_MPDU_MFLG2_AMSDU) {
        struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
        uint8_t subframe_idx = (desc->amsdu_info &
                                IWM_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK);
        if (subframe_idx > 0)
            rxi.rxi_flags |= IEEE80211_RXI_HWDEC_SAME_PN;
        if (ieee80211_has_qos(wh) && ieee80211_has_addr4(wh) &&
            mbuf_len(m) >= sizeof(struct ieee80211_qosframe_addr4)) {
            struct ieee80211_qosframe_addr4 *qwh4 = mtod(m,
                                                         struct ieee80211_qosframe_addr4 *);
            qwh4->i_qos[0] &= htole16(~IEEE80211_QOS_AMSDU);
            
            /* HW reverses addr3 and addr4. */
            iwm_flip_address(qwh4->i_addr3);
            iwm_flip_address(qwh4->i_addr4);
        } else if (ieee80211_has_qos(wh) &&
                   mbuf_len(m) >= sizeof(struct ieee80211_qosframe)) {
            struct ieee80211_qosframe *qwh = mtod(m,
                                                  struct ieee80211_qosframe *);
            qwh->i_qos[0] &= htole16(~IEEE80211_QOS_AMSDU);
            
            /* HW reverses addr3. */
            iwm_flip_address(qwh->i_addr3);
        }
    }
    
    /*
     * Verify decryption before duplicate detection. The latter uses
     * the TID supplied in QoS frame headers and this TID is implicitly
     * verified as part of the CCMP nonce.
     */
    if (iwm_rx_hwdecrypt(sc, m, le16toh(desc->status), &rxi)) {
        mbuf_freem(m);
        return;
    }
    
    if (iwm_detect_duplicate(sc, m, desc, &rxi)) {
        mbuf_freem(m);
        return;
    }
    
    phy_info = le16toh(desc->phy_info);
    rate_n_flags = le32toh(desc->v1.rate_n_flags);
    chanidx = desc->v1.channel;
    device_timestamp = desc->v1.gp2_on_air_rise;
    
    rssi = iwm_rxmq_get_signal_strength(sc, &rx_status, rate_n_flags, desc);
    rs_update_last_rssi(sc, &rx_status);
    rssi = (0 - IWM_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */
    
    rxi.rxi_rssi = rssi;
    rxi.rxi_tstamp = le64toh(desc->v1.tsf_on_air_rise);
    rxi.rxi_chan = chanidx;
    
    if (iwm_rx_reorder(sc, m, chanidx, desc,
                       (phy_info & IWM_RX_MPDU_PHY_SHORT_PREAMBLE),
                       rate_n_flags, device_timestamp, &rxi, ml))
        return;
    
    iwm_rx_frame(sc, m, chanidx, le16toh(desc->status),
                 (phy_info & IWM_RX_MPDU_PHY_SHORT_PREAMBLE),
                 rate_n_flags, device_timestamp, &rxi, ml);
}

int ItlIwm::
iwm_rx_pkt_valid(struct iwm_rx_packet *pkt)
{
    int qid, idx, code;
    
    qid = pkt->hdr.qid & ~0x80;
    idx = pkt->hdr.idx;
    code = IWM_WIDE_ID(pkt->hdr.flags, pkt->hdr.code);
    
    return (!(qid == 0 && idx == 0 && code == 0) &&
            pkt->len_n_flags != htole32(IWM_FH_RSCSR_FRAME_INVALID));
}

#define SYNC_RESP_STRUCT(_var_, _pkt_, t)                    \
do {                                    \
bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
sizeof(*(_var_)), BUS_DMASYNC_POSTREAD);            \
_var_ = (t)((_pkt_)+1);                    \
} while (/*CONSTCOND*/0)

void ItlIwm::
iwm_rx_pkt(struct iwm_softc *sc, struct iwm_rx_data *data, struct mbuf_list *ml)
{
    struct _ifnet *ifp = IC2IFP(&sc->sc_ic);
    struct iwm_rx_packet *pkt, *nextpkt;
    uint32_t offset = 0, nextoff = 0, nmpdu = 0, len;
    mbuf_t m0, m = NULL;
    const size_t minsz = sizeof(pkt->len_n_flags) + sizeof(pkt->hdr);
    int qid, idx, code, handled = 1;
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWM_RBUF_SIZE,
    //        BUS_DMASYNC_POSTREAD);
    m0 = data->m;
    while (m0 && offset + minsz < IWM_RBUF_SIZE) {
        pkt = (struct iwm_rx_packet *)((uint8_t*)mbuf_data(m0) + offset);
        qid = pkt->hdr.qid;
        idx = pkt->hdr.idx;
        
        code = IWM_WIDE_ID(pkt->hdr.flags, pkt->hdr.code);
        
        if (!iwm_rx_pkt_valid(pkt))
            break;
        
        len = sizeof(pkt->len_n_flags) + iwm_rx_packet_len(pkt);
        if (len < minsz || len > (IWM_RBUF_SIZE - offset))
            break;
        
        if (code == IWM_REPLY_RX_MPDU_CMD && ++nmpdu == 1) {
            /* Take mbuf m0 off the RX ring. */
            if (iwm_rx_addbuf(sc, IWM_RBUF_SIZE, sc->rxq.cur)) {
                ifp->netStat->inputErrors++;
                break;
            }
            
//            KASSERT(data->m != m0, "data->m != m0");
        }
        
        switch (code) {
            case IWM_REPLY_RX_PHY_CMD:
                iwm_rx_rx_phy_cmd(sc, pkt, data);
                break;
                
            case IWM_REPLY_RX_MPDU_CMD: {
                size_t maxlen = IWM_RBUF_SIZE - offset - minsz;
                nextoff = offset +
                roundup(len, IWM_FH_RSCSR_FRAME_ALIGN);
                nextpkt = (struct iwm_rx_packet *)
                ((uint8_t*)mbuf_data(m0) + nextoff);
                if (nextoff + minsz >= IWM_RBUF_SIZE ||
                    !iwm_rx_pkt_valid(nextpkt)) {
                    /* No need to copy last frame in buffer. */
                    if (offset > 0)
                        mbuf_adj(m0, offset);
                    if (sc->sc_mqrx_supported)
                        iwm_rx_mpdu_mq(sc, m0, pkt->data,
                                       maxlen, ml);
                    else
                        iwm_rx_mpdu(sc, m0, pkt->data,
                                    maxlen, ml);
                    m0 = NULL; /* stack owns m0 now; abort loop */
                } else {
                    /*
                     * Create an mbuf which points to the current
                     * packet. Always copy from offset zero to
                     * preserve m_pkthdr.
                     */
                    mbuf_copym(m0, 0, MBUF_COPYALL, MBUF_DONTWAIT, &m);
                    //                m = m_copym(m0, 0, M_COPYALL, M_DONTWAIT);
                    if (m == NULL) {
                        ifp->netStat->inputErrors++;
                        mbuf_freem(m0);
                        m0 = NULL;
                        break;
                    }
                    mbuf_adj(m, offset);
                    if (sc->sc_mqrx_supported)
                        iwm_rx_mpdu_mq(sc, m, pkt->data,
                                       maxlen, ml);
                    else
                        iwm_rx_mpdu(sc, m, pkt->data,
                                    maxlen, ml);
                }
                
                break;
            }
                
            case IWM_TX_CMD:
                iwm_rx_tx_cmd(sc, pkt, data);
                break;
            case IWM_BA_NOTIF:
                iwm_rx_tx_ba_notif(sc, pkt, data);
                break;
                
            case IWM_MISSED_BEACONS_NOTIFICATION:
                iwm_rx_bmiss(sc, pkt, data);
                break;
                
            case IWM_MFUART_LOAD_NOTIFICATION:
                break;
                
            case IWM_ALIVE: {
                struct iwm_alive_resp_v1 *resp1;
                struct iwm_alive_resp_v2 *resp2;
                struct iwm_alive_resp_v3 *resp3;

//                XYLog("%s: firmware alive, size=%d\n", __FUNCTION__, iwm_rx_packet_payload_len(pkt));

                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp1)) {
                    SYNC_RESP_STRUCT(resp1, pkt, struct iwm_alive_resp_v1 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp1->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp1->log_event_table_ptr);
                    sc->sched_base = le32toh(resp1->scd_base_ptr);
                    if (resp1->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp2)) {
                    SYNC_RESP_STRUCT(resp2, pkt, struct iwm_alive_resp_v2 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp2->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp2->log_event_table_ptr);
                    sc->sched_base = le32toh(resp2->scd_base_ptr);
                    sc->sc_uc.uc_umac_error_event_table
                    = le32toh(resp2->error_info_addr);
                    if (resp2->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                if (iwm_rx_packet_payload_len(pkt) == sizeof(*resp3)) {
                    SYNC_RESP_STRUCT(resp3, pkt, struct iwm_alive_resp_v3 *);
                    sc->sc_uc.uc_error_event_table
                    = le32toh(resp3->error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table
                    = le32toh(resp3->log_event_table_ptr);
                    sc->sched_base = le32toh(resp3->scd_base_ptr);
                    sc->sc_uc.uc_umac_error_event_table
                    = le32toh(resp3->error_info_addr);
                    if (resp3->status == IWM_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                }
                
                sc->sc_uc.uc_intr = 1;
                wakeupOn(&sc->sc_uc);
                break;
            }
                
            case IWM_CALIB_RES_NOTIF_PHY_DB: {
                struct iwm_calib_res_notif_phy_db *phy_db_notif;
                SYNC_RESP_STRUCT(phy_db_notif, pkt, struct iwm_calib_res_notif_phy_db *);
                iwm_phy_db_set_section(sc, phy_db_notif);
                sc->sc_init_complete |= IWM_CALIB_COMPLETE;
                //                wakeupOn(&sc->sc_init_complete);
                break;
            }
                
            case IWM_STATISTICS_NOTIFICATION: {
                struct iwm_notif_statistics *stats;
                SYNC_RESP_STRUCT(stats, pkt, struct iwm_notif_statistics *);
                memcpy(&sc->sc_stats, stats, sizeof(sc->sc_stats));
                sc->sc_noise = iwm_get_noise(&stats->rx.general);
                break;
            }
                
            case IWM_MCC_CHUB_UPDATE_CMD: {
                struct iwm_mcc_chub_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_mcc_chub_notif *);
                iwm_mcc_update(sc, notif);
                break;
            }
                
            case IWM_DTS_MEASUREMENT_NOTIFICATION:
            case IWM_WIDE_ID(IWM_PHY_OPS_GROUP,
                             IWM_DTS_MEASUREMENT_NOTIF_WIDE):
            case IWM_WIDE_ID(IWM_PHY_OPS_GROUP,
                             IWM_TEMP_REPORTING_THRESHOLDS_CMD):
                break;

            case IWM_WIDE_ID(IWM_PHY_OPS_GROUP,
                             IWM_CT_KILL_NOTIFICATION): {
                struct iwm_ct_kill_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_ct_kill_notif *);
                XYLog("%s: device at critical temperature (%u degC), "
                       "stopping device\n",
                       DEVNAME(sc), le16toh(notif->temperature));
                sc->sc_flags |= IWM_FLAG_HW_ERR;
                task_add(systq, &sc->init_task);
                break;
            }
                
            case IWM_ADD_STA_KEY:
            case IWM_PHY_CONFIGURATION_CMD:
            case IWM_TX_ANT_CONFIGURATION_CMD:
            case IWM_ADD_STA:
            case IWM_MAC_CONTEXT_CMD:
            case IWM_REPLY_SF_CFG_CMD:
            case IWM_POWER_TABLE_CMD:
            case IWM_LTR_CONFIG:
            case IWM_PHY_CONTEXT_CMD:
            case IWM_BINDING_CONTEXT_CMD:
            case IWM_WIDE_ID(IWM_LONG_GROUP, IWM_SCAN_CFG_CMD):
            case IWM_WIDE_ID(IWM_LONG_GROUP, IWM_SCAN_REQ_UMAC):
            case IWM_WIDE_ID(IWM_LONG_GROUP, IWM_SCAN_ABORT_UMAC):
            case IWM_SCAN_OFFLOAD_REQUEST_CMD:
            case IWM_SCAN_OFFLOAD_ABORT_CMD:
            case IWM_REPLY_BEACON_FILTERING_CMD:
            case IWM_MAC_PM_POWER_TABLE:
            case IWM_TIME_QUOTA_CMD:
            case IWM_REMOVE_STA:
            case IWM_TXPATH_FLUSH:
            case IWM_LQ_CMD:
            case IWM_WIDE_ID(IWM_LONG_GROUP,
                             IWM_FW_PAGING_BLOCK_CMD):
            case IWM_BT_CONFIG:
            case IWM_REPLY_THERMAL_MNG_BACKOFF:
            case IWM_NVM_ACCESS_CMD:
            case IWM_MCC_UPDATE_CMD:
            case IWM_TIME_EVENT_CMD: {
                size_t pkt_len;
                
                if (sc->sc_cmd_resp_pkt[idx] == NULL)
                    break;
                
                //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
                //                sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                
                pkt_len = sizeof(pkt->len_n_flags) +
                iwm_rx_packet_len(pkt);
                
                if ((pkt->hdr.flags & IWM_CMD_FAILED_MSK) ||
                    pkt_len < sizeof(*pkt) ||
                    pkt_len > sc->sc_cmd_resp_len[idx]) {
                    ::free(sc->sc_cmd_resp_pkt[idx]);
                    sc->sc_cmd_resp_pkt[idx] = NULL;
                    break;
                }
                
                //            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
                //                pkt_len - sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                memcpy(sc->sc_cmd_resp_pkt[idx], pkt, pkt_len);
                break;
            }
                
                /* ignore */
            case IWM_PHY_DB_CMD:
                break;
                
            case IWM_INIT_COMPLETE_NOTIF:
                sc->sc_init_complete |= IWM_INIT_COMPLETE;
                wakeupOn(&sc->sc_init_complete);
                break;
                
            case IWM_SCAN_OFFLOAD_COMPLETE: {
                struct iwm_periodic_scan_complete *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_periodic_scan_complete *);
                break;
            }
                
            case IWM_SCAN_ITERATION_COMPLETE: {
                struct iwm_lmac_scan_complete_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_lmac_scan_complete_notif *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_SCAN_COMPLETE_UMAC: {
                struct iwm_umac_scan_complete *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_umac_scan_complete *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_SCAN_ITERATION_COMPLETE_UMAC: {
                struct iwm_umac_scan_iter_complete_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_umac_scan_iter_complete_notif *);
                iwm_endscan(sc);
                break;
            }
                
            case IWM_REPLY_ERROR: {
                struct iwm_error_resp *resp;
                SYNC_RESP_STRUCT(resp, pkt, struct iwm_error_resp *);
                XYLog("%s: firmware error 0x%x, cmd 0x%x\n",
                      DEVNAME(sc), le32toh(resp->error_type),
                      resp->cmd_id);
                break;
            }
                
            case IWM_TIME_EVENT_NOTIFICATION: {
                struct iwm_time_event_notif *notif;
                uint32_t action;
                SYNC_RESP_STRUCT(notif, pkt, struct iwm_time_event_notif *);
                
                if (sc->sc_time_event_uid != le32toh(notif->unique_id))
                    break;
                action = le32toh(notif->action);
                if (action & IWM_TE_V2_NOTIF_HOST_EVENT_END)
                    sc->sc_flags &= ~IWM_FLAG_TE_ACTIVE;
                break;
            }
                
            case IWM_WIDE_ID(IWM_SYSTEM_GROUP,
                             IWM_FSEQ_VER_MISMATCH_NOTIFICATION):
                break;
                
                /*
                 * Firmware versions 21 and 22 generate some DEBUG_LOG_MSG
                 * messages. Just ignore them for now.
                 */
            case IWM_DEBUG_LOG_MSG:
                break;
                
            case IWM_MCAST_FILTER_CMD:
                break;
                
            case IWM_SCD_QUEUE_CFG: {
                struct iwm_scd_txq_cfg_rsp *rsp;
                SYNC_RESP_STRUCT(rsp, pkt, struct iwm_scd_txq_cfg_rsp *);
                
                break;
            }
                
            case IWM_WIDE_ID(IWM_DATA_PATH_GROUP, IWM_DQA_ENABLE_CMD):
                break;

            case IWM_WIDE_ID(IWM_SYSTEM_GROUP, IWM_SOC_CONFIGURATION_CMD):
                break;
                
            default:
                handled = 0;
                XYLog("%s: unhandled firmware response 0x%x/0x%x "
                      "rx ring %d[%d]\n",
                      DEVNAME(sc), code, pkt->len_n_flags,
                      (qid & ~0x80), idx);
                break;
        }
        
        /*
         * uCode sets bit 0x80 when it originates the notification,
         * i.e. when the notification is not a direct response to a
         * command sent by the driver.
         * For example, uCode issues IWM_REPLY_RX when it sends a
         * received frame to the driver.
         */
        if (handled && !(qid & (1 << 7))) {
            iwm_cmd_done(sc, qid, idx, code);
        }
        
        offset += roundup(len, IWM_FH_RSCSR_FRAME_ALIGN);
    }
    
    if (m0 && m0 != data->m && mbuf_type(m0) != MBUF_TYPE_FREE) {
        mbuf_freem(m0);
    }
}
