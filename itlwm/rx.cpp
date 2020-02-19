//
//  rx.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

void itlwm::
iwm_disable_rx_dma(struct iwm_softc *sc)
{
    int ntries;

    if (iwm_nic_lock(sc)) {
        IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
        for (ntries = 0; ntries < 1000; ntries++) {
            if (IWM_READ(sc, IWM_FH_MEM_RSSR_RX_STATUS_REG) &
                IWM_FH_RSSR_CHNL0_RX_STATUS_CHNL_IDLE)
                break;
            DELAY(10);
        }
        iwm_nic_unlock(sc);
    }
}

void itlwm::
iwm_reset_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    ring->cur = 0;
//    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
//        ring->stat_dma.size, BUS_DMASYNC_PREWRITE);
    memset(ring->stat, 0, sizeof(*ring->stat));
//    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
//        ring->stat_dma.size, BUS_DMASYNC_POSTWRITE);

}

void itlwm::
iwm_free_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    int i;

    iwm_dma_contig_free(&ring->desc_dma);
    iwm_dma_contig_free(&ring->stat_dma);

    for (i = 0; i < IWM_RX_RING_COUNT; i++) {
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

int itlwm::
iwm_alloc_rx_ring(struct iwm_softc *sc, struct iwm_rx_ring *ring)
{
    bus_size_t size;
    int i, err;

    ring->cur = 0;

    /* Allocate RX descriptors (256-byte aligned). */
    size = IWM_RX_RING_COUNT * sizeof(uint32_t);
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, (void**)&ring->desc, size, 256);
    if (err) {
        printf("%s: could not allocate RX ring DMA memory\n",
            DEVNAME(sc));
        goto fail;
    }

    /* Allocate RX status area (16-byte aligned). */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &ring->stat_dma, (void**)&ring->stat,
        sizeof(struct iwm_rb_status), 16);
    if (err) {
        printf("%s: could not allocate RX status DMA memory\n",
            DEVNAME(sc));
        goto fail;
    }
    ring->stat = (struct iwm_rb_status*)ring->stat_dma.vaddr;

    for (i = 0; i < IWM_RX_RING_COUNT; i++) {
        struct iwm_rx_data *data = &ring->data[i];

        memset(data, 0, sizeof(*data));
        err = bus_dmamap_create(sc->sc_dmat, IWM_RBUF_SIZE, 1,
            IWM_RBUF_SIZE, 0, BUS_DMA_NOWAIT,
            &data->map);
        if (err) {
            printf("%s: could not create RX buf DMA map\n",
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

int itlwm::
iwm_rx_addbuf(struct iwm_softc *sc, int size, int idx)
{
//    struct iwm_rx_ring *ring = &sc->rxq;
//    struct iwm_rx_data *data = &ring->data[idx];
//    mbuf_t m;
//    int err;
//    int fatal = 0;
//
//    mbuf_gethdr(MBUF_DONTWAIT, MT_DATA, &m);
//    if (m == NULL)
//        return ENOBUFS;
//
//    if (size <= MCLBYTES) {
//        MCLGET(m, M_DONTWAIT);
//    } else {
//        MCLGETI(m, M_DONTWAIT, NULL, IWM_RBUF_SIZE);
//    }
//    if ((mbuf_flags(m) & M_EXT) == 0) {
//        mbuf_freem(m);
//        return ENOBUFS;
//    }
//
//    if (data->m != NULL) {
//        bus_dmamap_unload(sc->sc_dmat, data->map);
//        fatal = 1;
//    }
//
//    m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;
//    err = bus_dmamap_load_mbuf(sc->sc_dmat, data->map, m,
//        BUS_DMA_READ|BUS_DMA_NOWAIT);
//    if (err) {
//        /* XXX */
//        if (fatal)
//            panic("iwm: could not load RX mbuf");
//        mbuf_freem(m);
//        return err;
//    }
//    data->m = m;
//    bus_dmamap_sync(sc->sc_dmat, data->map, 0, size, BUS_DMASYNC_PREREAD);
//
//    /* Update RX descriptor. */
//    ring->desc[idx] = htole32(data->map->dm_segs[0].location >> 8);
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//        idx * sizeof(uint32_t), sizeof(uint32_t), BUS_DMASYNC_PREWRITE);

    return 0;
}

void itlwm::
iwm_rx_rx_phy_cmd(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
    struct iwm_rx_data *data)
{
    struct iwm_rx_phy_info *phy_info = (struct iwm_rx_phy_info *)pkt->data;

    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
        sizeof(*phy_info), BUS_DMASYNC_POSTREAD);

    memcpy(&sc->sc_last_phy_info, phy_info, sizeof(sc->sc_last_phy_info));
}
