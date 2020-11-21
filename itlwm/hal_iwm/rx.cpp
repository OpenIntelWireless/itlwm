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
/*    $OpenBSD: if_iwm.c,v 1.313 2020/07/10 13:22:20 patrick Exp $    */

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
        if (data->map != NULL)
            bus_dmamap_destroy(sc->sc_dmat, data->map);
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
    struct iwm_rx_phy_info *phy_info;
    struct iwm_rx_mpdu_res_start *rx_res;
    int device_timestamp;
    uint16_t phy_flags;
    uint32_t len;
    uint32_t rx_pkt_status;
    int rssi, chanidx, rate_n_flags;
    
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
    
    chanidx = letoh32(phy_info->channel);
    device_timestamp = le32toh(phy_info->system_timestamp);
    phy_flags = letoh16(phy_info->phy_flags);
    rate_n_flags = le32toh(phy_info->rate_n_flags);

    rssi = iwm_get_signal_strength(sc, phy_info);
    rssi = (0 - IWM_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */

    memset(&rxi, 0, sizeof(rxi));
    rxi.rxi_rssi = rssi;
    rxi.rxi_tstamp = device_timestamp;
    
    iwm_rx_frame(sc, m, chanidx, rx_pkt_status,
                 (phy_flags & IWM_PHY_INFO_FLAG_SHPREAMBLE),
                 rate_n_flags, device_timestamp, &rxi, ml);
}

void ItlIwm::
iwm_rx_mpdu_mq(struct iwm_softc *sc, mbuf_t m, void *pktdata,
               size_t maxlen, struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_rxinfo rxi;
    struct iwm_rx_mpdu_desc *desc;
    uint32_t len, hdrlen, rate_n_flags, device_timestamp;
    int rssi;
    uint8_t chanidx;
    uint16_t phy_info;
    
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
    
    phy_info = le16toh(desc->phy_info);
    rate_n_flags = le32toh(desc->v1.rate_n_flags);
    chanidx = desc->v1.channel;
    device_timestamp = desc->v1.gp2_on_air_rise;

    rssi = iwm_rxmq_get_signal_strength(sc, desc);
    rssi = (0 - IWM_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */

    memset(&rxi, 0, sizeof(rxi));
    rxi.rxi_rssi = rssi;
    rxi.rxi_tstamp = le64toh(desc->v1.tsf_on_air_rise);

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
    size_t remain = IWM_RBUF_SIZE;
    int qid, idx, code, handled = 1;
    bool replaced = false;
    
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
        if (len < sizeof(pkt->hdr) ||
            len > (IWM_RBUF_SIZE - offset - minsz))
            break;
        
        if (code == IWM_REPLY_RX_MPDU_CMD && ++nmpdu == 1) {
            /* Take mbuf m0 off the RX ring. */
//            mbuf_t mm;
//            mm = replaceOrCopyPacket(&m0, IWM_RBUF_SIZE, &replaced);
//            if (!mm) {
//                XYLog("%s replaceOrCopyPacket fail\n", __FUNCTION__);
//                ifp->netStat->inputErrors++;
//                break;
//            }
//            if (replaced) {
//                struct iwm_rx_ring *ring = &sc->rxq;
//                struct iwm_rx_data *data = &ring->data[sc->rxq.cur];
//                data->map->dm_nsegs = data->map->cursor->getPhysicalSegments(mm, &data->map->dm_segs[0], 1);
//                if (data->map->dm_nsegs == 0) {
//                    XYLog("%s data->map->dm_nsegs == 0\n", __FUNCTION__);
//                    freePacket(mm);
//                    ifp->netStat->inputErrors++;
//                    break;
//                }
//                if (sc->sc_mqrx_supported) {
//                    ((uint64_t *)ring->desc)[sc->rxq.cur] =
//                    htole64(data->map->dm_segs[0].location);
//                } else {
//                    ((uint32_t *)ring->desc)[sc->rxq.cur] =
//                    htole32(data->map->dm_segs[0].location >> 8);
//                }
//                mbuf_setlen(mm, IWM_RBUF_SIZE);
//                data->m = mm;
//            }
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
                size_t maxlen = remain - minsz;
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
                
                if (offset + minsz < remain)
                    remain -= offset;
                else
                    remain = minsz;
                break;
            }
                
            case IWM_TX_CMD:
                iwm_rx_tx_cmd(sc, pkt, data);
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
                
                sc->sc_fw_mcc[0] = (notif->mcc & 0xff00) >> 8;
                sc->sc_fw_mcc[1] = notif->mcc & 0xff;
                sc->sc_fw_mcc[2] = '\0';

                if (sc->sc_fw_mcc_int != notif->mcc && sc->sc_ic.ic_event_handler) {
                    (*sc->sc_ic.ic_event_handler)(&sc->sc_ic, IEEE80211_EVT_COUNTRY_CODE_UPDATE, NULL);
                }

                sc->sc_fw_mcc_int = notif->mcc;
            }
                
            case IWM_DTS_MEASUREMENT_NOTIFICATION:
            case IWM_WIDE_ID(IWM_PHY_OPS_GROUP,
                             IWM_DTS_MEASUREMENT_NOTIF_WIDE):
                break;
                
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
