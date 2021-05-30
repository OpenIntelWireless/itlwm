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

struct iwm_phy_db_entry * ItlIwm::
iwm_phy_db_get_section(struct iwm_softc *sc, uint16_t type, uint16_t chg_id)
{
    struct iwm_phy_db *phy_db = &sc->sc_phy_db;
    
    if (type >= IWM_PHY_DB_MAX)
        return NULL;
    
    switch (type) {
        case IWM_PHY_DB_CFG:
            return &phy_db->cfg;
        case IWM_PHY_DB_CALIB_NCH:
            return &phy_db->calib_nch;
        case IWM_PHY_DB_CALIB_CHG_PAPD:
            if (chg_id >= IWM_NUM_PAPD_CH_GROUPS)
                return NULL;
            return &phy_db->calib_ch_group_papd[chg_id];
        case IWM_PHY_DB_CALIB_CHG_TXP:
            if (chg_id >= IWM_NUM_TXP_CH_GROUPS)
                return NULL;
            return &phy_db->calib_ch_group_txp[chg_id];
        default:
            return NULL;
    }
    return NULL;
}

int ItlIwm::
iwm_phy_db_set_section(struct iwm_softc *sc,
                       struct iwm_calib_res_notif_phy_db *phy_db_notif)
{
    uint16_t type = le16toh(phy_db_notif->type);
    uint16_t size  = le16toh(phy_db_notif->length);
    struct iwm_phy_db_entry *entry;
    uint16_t chg_id = 0;
    
    if (type == IWM_PHY_DB_CALIB_CHG_PAPD ||
        type == IWM_PHY_DB_CALIB_CHG_TXP)
        chg_id = le16toh(*(uint16_t *)phy_db_notif->data);
    
    entry = iwm_phy_db_get_section(sc, type, chg_id);
    if (!entry)
        return EINVAL;
    
    if (entry->data)
        ::free(entry->data);
    entry->data = (uint8_t*)malloc(size, M_DEVBUF, M_NOWAIT);
    if (!entry->data) {
        entry->size = 0;
        return ENOMEM;
    }
    memcpy(entry->data, phy_db_notif->data, size);
    entry->size = size;
    
    return 0;
}

int ItlIwm::
iwm_phy_db_get_section_data(struct iwm_softc *sc, uint32_t type, uint8_t **data,
                            uint16_t *size, uint16_t ch_id)
{
    struct iwm_phy_db_entry *entry;
    uint16_t ch_group_id = 0;
    
    if (type == IWM_PHY_DB_CALIB_CHG_PAPD)
        ch_group_id = iwm_channel_id_to_papd(ch_id);
    else if (type == IWM_PHY_DB_CALIB_CHG_TXP)
        ch_group_id = iwm_channel_id_to_txp(sc, ch_id);
    
    entry = iwm_phy_db_get_section(sc, type, ch_group_id);
    if (!entry)
        return EINVAL;
    
    *data = entry->data;
    *size = entry->size;
    
    return 0;
}

int ItlIwm::
iwm_send_phy_db_cmd(struct iwm_softc *sc, uint16_t type, uint16_t length,
                    void *data)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_phy_db_cmd phy_db_cmd;
    struct iwm_host_cmd cmd = {
        .id = IWM_PHY_DB_CMD,
        .flags = IWM_CMD_ASYNC,
    };
    
    phy_db_cmd.type = le16toh(type);
    phy_db_cmd.length = le16toh(length);
    
    cmd.data[0] = &phy_db_cmd;
    cmd.len[0] = sizeof(struct iwm_phy_db_cmd);
    cmd.data[1] = data;
    cmd.len[1] = length;
    
    return iwm_send_cmd(sc, &cmd);
}

int ItlIwm::
iwm_phy_db_send_all_channel_groups(struct iwm_softc *sc, uint16_t type,
                                   uint8_t max_ch_groups)
{
    XYLog("%s\n", __FUNCTION__);
    uint16_t i;
    int err;
    struct iwm_phy_db_entry *entry;
    
    for (i = 0; i < max_ch_groups; i++) {
        entry = iwm_phy_db_get_section(sc, type, i);
        if (!entry)
            return EINVAL;
        
        if (!entry->size)
            continue;
        
        err = iwm_send_phy_db_cmd(sc, type, entry->size, entry->data);
        if (err)
            return err;
        
        DELAY(1000);
    }
    
    return 0;
}

int ItlIwm::
iwm_send_phy_db_data(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    uint8_t *data = NULL;
    uint16_t size = 0;
    int err;
    
    err = iwm_phy_db_get_section_data(sc, IWM_PHY_DB_CFG, &data, &size, 0);
    if (err)
        return err;
    
    err = iwm_send_phy_db_cmd(sc, IWM_PHY_DB_CFG, size, data);
    if (err)
        return err;
    
    err = iwm_phy_db_get_section_data(sc, IWM_PHY_DB_CALIB_NCH,
                                      &data, &size, 0);
    if (err)
        return err;
    
    err = iwm_send_phy_db_cmd(sc, IWM_PHY_DB_CALIB_NCH, size, data);
    if (err)
        return err;
    
    err = iwm_phy_db_send_all_channel_groups(sc,
                                             IWM_PHY_DB_CALIB_CHG_PAPD, IWM_NUM_PAPD_CH_GROUPS);
    if (err)
        return err;
    
    err = iwm_phy_db_send_all_channel_groups(sc,
                                             IWM_PHY_DB_CALIB_CHG_TXP, IWM_NUM_TXP_CH_GROUPS);
    if (err)
        return err;
    
    return 0;
}

/*
 * For the high priority TE use a time event type that has similar priority to
 * the FW's action scan priority.
 */
#define IWM_ROC_TE_TYPE_NORMAL IWM_TE_P2P_DEVICE_DISCOVERABLE
#define IWM_ROC_TE_TYPE_MGMT_TX IWM_TE_P2P_CLIENT_ASSOC

int ItlIwm::
iwm_send_time_event_cmd(struct iwm_softc *sc,
                        const struct iwm_time_event_cmd *cmd)
{
    struct iwm_rx_packet *pkt;
    struct iwm_time_event_resp *resp;
    struct iwm_host_cmd hcmd = {
        .id = IWM_TIME_EVENT_CMD,
        .flags = IWM_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(*pkt) + sizeof(*resp),
    };
    uint32_t resp_len;
    int err;
    
    hcmd.data[0] = cmd;
    hcmd.len[0] = sizeof(*cmd);
    err = iwm_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.flags & IWM_CMD_FAILED_MSK)) {
        err = EIO;
        goto out;
    }
    
    resp_len = iwm_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        err = EIO;
        goto out;
    }
    
    resp = (struct iwm_time_event_resp *)pkt->data;
    if (le32toh(resp->status) == 0)
        sc->sc_time_event_uid = le32toh(resp->unique_id);
    else
        err = EIO;
out:
    iwm_free_resp(sc, &hcmd);
    return err;
}

void ItlIwm::
iwm_protect_session(struct iwm_softc *sc, struct iwm_node *in,
                    uint32_t duration, uint32_t max_delay)
{
    struct iwm_time_event_cmd time_cmd;
    
    /* Do nothing if a time event is already scheduled. */
    if (sc->sc_flags & IWM_FLAG_TE_ACTIVE)
        return;
    
    memset(&time_cmd, 0, sizeof(time_cmd));
    
    time_cmd.action = htole32(IWM_FW_CTXT_ACTION_ADD);
    time_cmd.id_and_color =
    htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    time_cmd.id = htole32(IWM_TE_BSS_STA_AGGRESSIVE_ASSOC);
    
    time_cmd.apply_time = htole32(0);
    
    time_cmd.max_frags = IWM_TE_V2_FRAG_NONE;
    time_cmd.max_delay = htole32(max_delay);
    /* TODO: why do we need to interval = bi if it is not periodic? */
    time_cmd.interval = htole32(1);
    time_cmd.duration = htole32(duration);
    time_cmd.repeat = 1;
    time_cmd.policy
    = htole16(IWM_TE_V2_NOTIF_HOST_EVENT_START |
              IWM_TE_V2_NOTIF_HOST_EVENT_END |
              IWM_T2_V2_START_IMMEDIATELY);
    
    if (iwm_send_time_event_cmd(sc, &time_cmd) == 0)
        sc->sc_flags |= IWM_FLAG_TE_ACTIVE;
    
    DELAY(100);
}

void ItlIwm::
iwm_unprotect_session(struct iwm_softc *sc, struct iwm_node *in)
{
    struct iwm_time_event_cmd time_cmd;
    
    /* Do nothing if the time event has already ended. */
    if ((sc->sc_flags & IWM_FLAG_TE_ACTIVE) == 0)
        return;
    
    memset(&time_cmd, 0, sizeof(time_cmd));
    
    time_cmd.action = htole32(IWM_FW_CTXT_ACTION_REMOVE);
    time_cmd.id_and_color =
    htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    time_cmd.id = htole32(sc->sc_time_event_uid);
    
    if (iwm_send_time_event_cmd(sc, &time_cmd) == 0)
        sc->sc_flags &= ~IWM_FLAG_TE_ACTIVE;
    
    DELAY(100);
}

int ItlIwm::
iwm_send_phy_cfg_cmd(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_phy_cfg_cmd phy_cfg_cmd;
    enum iwm_ucode_type ucode_type = sc->sc_uc_current;
    
    phy_cfg_cmd.phy_cfg = htole32(sc->sc_fw_phy_config);
    phy_cfg_cmd.calib_control.event_trigger =
    sc->sc_default_calib[ucode_type].event_trigger;
    phy_cfg_cmd.calib_control.flow_trigger =
    sc->sc_default_calib[ucode_type].flow_trigger;
    
    return iwm_send_cmd_pdu(sc, IWM_PHY_CONFIGURATION_CMD, 0,
                            sizeof(phy_cfg_cmd), &phy_cfg_cmd);
}

int ItlIwm::
iwm_send_dqa_cmd(struct iwm_softc *sc)
{
    struct iwm_dqa_enable_cmd dqa_cmd = {
        .cmd_queue = htole32(IWM_DQA_CMD_QUEUE),
    };
    uint32_t cmd_id;
    
    cmd_id = iwm_cmd_id(IWM_DQA_ENABLE_CMD, IWM_DATA_PATH_GROUP, 0);
    return iwm_send_cmd_pdu(sc, cmd_id, 0, sizeof(dqa_cmd), &dqa_cmd);
}

int ItlIwm::
iwm_binding_cmd(struct iwm_softc *sc, struct iwm_node *in, uint32_t action)
{
    struct iwm_binding_cmd cmd;
    struct iwm_phy_ctxt *phyctxt = in->in_phyctxt;
    uint32_t mac_id = IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color);
    int i, err, active = (sc->sc_flags & IWM_FLAG_BINDING_ACTIVE);
    uint32_t status;
    
    if (action == IWM_FW_CTXT_ACTION_ADD && active)
        panic("binding already added");
    if (action == IWM_FW_CTXT_ACTION_REMOVE && !active)
        panic("binding already removed");
    
    if (phyctxt == NULL) /* XXX race with iwm_stop() */
        return EINVAL;
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.id_and_color
    = htole32(IWM_FW_CMD_ID_AND_COLOR(phyctxt->id, phyctxt->color));
    cmd.action = htole32(action);
    cmd.phy = htole32(IWM_FW_CMD_ID_AND_COLOR(phyctxt->id, phyctxt->color));
    
    cmd.macs[0] = htole32(mac_id);
    for (i = 1; i < IWM_MAX_MACS_IN_BINDING; i++)
        cmd.macs[i] = htole32(IWM_FW_CTXT_INVALID);
    
    status = 0;
    err = iwm_send_cmd_pdu_status(sc, IWM_BINDING_CONTEXT_CMD,
                                  sizeof(cmd), &cmd, &status);
    if (err == 0 && status != 0)
        err = EIO;
    
    return err;
}

int ItlIwm::
iwm_send_cmd(struct iwm_softc *sc, struct iwm_host_cmd *hcmd)
{
    struct iwm_tx_ring *ring = &sc->txq[sc->cmdqid];
    struct iwm_tfd *desc;
    struct iwm_tx_data *txdata;
    struct iwm_device_cmd *cmd;
    mbuf_t m;
    bus_addr_t paddr;
    uint32_t addr_lo;
    int err = 0, i, paylen, off, s;
    int idx, code, async, group_id;
    size_t hdrlen, datasz;
    uint8_t *data;
    int generation = sc->sc_generation;
    unsigned int max_chunks = 1;
    IOPhysicalSegment seg;
    
    code = hcmd->id;
    async = hcmd->flags & IWM_CMD_ASYNC;
    idx = ring->cur;
    
    for (i = 0, paylen = 0; i < nitems(hcmd->len); i++) {
        paylen += hcmd->len[i];
    }
    
    /* If this command waits for a response, allocate response buffer. */
    hcmd->resp_pkt = NULL;
    if (hcmd->flags & IWM_CMD_WANT_RESP) {
        uint8_t *resp_buf;
        _KASSERT(!async);
        _KASSERT(hcmd->resp_pkt_len >= sizeof(struct iwm_rx_packet));
        _KASSERT(hcmd->resp_pkt_len <= IWM_CMD_RESP_MAX);
        if (sc->sc_cmd_resp_pkt[idx] != NULL)
            return ENOSPC;
        resp_buf = (uint8_t *)malloc(hcmd->resp_pkt_len, M_DEVBUF,
                                     M_NOWAIT | M_ZERO);
        if (resp_buf == NULL)
            return ENOMEM;
        sc->sc_cmd_resp_pkt[idx] = resp_buf;
        sc->sc_cmd_resp_len[idx] = hcmd->resp_pkt_len;
    } else {
        sc->sc_cmd_resp_pkt[idx] = NULL;
    }
    
    s = splnet();
    
    desc = &ring->desc[idx];
    txdata = &ring->data[idx];
    
    group_id = iwm_cmd_groupid(code);
    if (group_id != 0) {
        hdrlen = sizeof(cmd->hdr_wide);
        datasz = sizeof(cmd->data_wide);
    } else {
        hdrlen = sizeof(cmd->hdr);
        datasz = sizeof(cmd->data);
    }
    
    if (paylen > datasz) {
        /* Command is too large to fit in pre-allocated space. */
        size_t totlen = hdrlen + paylen;
        if (paylen > IWM_MAX_CMD_PAYLOAD_SIZE) {
            XYLog("%s: firmware command too long (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            err = EINVAL;
            goto out;
        }
        mbuf_allocpacket(MBUF_WAITOK, totlen, &max_chunks, &m);
        if (m == NULL) {
            XYLog("%s: could not get fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            err = ENOMEM;
            goto out;
        }
        mbuf_setlen(m, totlen);
        mbuf_pkthdr_setlen(m, totlen);
        cmd = mtod(m, struct iwm_device_cmd *);
        txdata->map->dm_nsegs = txdata->map->cursor->getPhysicalSegmentsWithCoalesce(m, &seg, 1);
        if (txdata->map->dm_nsegs == 0) {
            XYLog("%s: could not load fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            mbuf_freem(m);
            goto out;
        }
//        XYLog("map fw cmd dm_nsegs=%d\n", txdata->map->dm_nsegs);
        txdata->m = m; /* mbuf will be freed in iwm_cmd_done() */
        paddr = seg.location;
    } else {
        cmd = &ring->cmd[idx];
        paddr = txdata->cmd_paddr;
    }
    
    if (group_id != 0) {
        cmd->hdr_wide.opcode = iwm_cmd_opcode(code);
        cmd->hdr_wide.group_id = group_id;
        cmd->hdr_wide.qid = ring->qid;
        cmd->hdr_wide.idx = idx;
        cmd->hdr_wide.length = htole16(paylen);
        cmd->hdr_wide.version = iwm_cmd_version(code);
        data = cmd->data_wide;
    } else {
        cmd->hdr.code = code;
        cmd->hdr.flags = 0;
        cmd->hdr.qid = ring->qid;
        cmd->hdr.idx = idx;
        data = cmd->data;
    }
    
    for (i = 0, off = 0; i < nitems(hcmd->data); i++) {
        if (hcmd->len[i] == 0)
            continue;
        memcpy(data + off, hcmd->data[i], hcmd->len[i]);
        off += hcmd->len[i];
    }
    KASSERT(off == paylen, "off == paylen");
    
    /* lo field is not aligned */
    addr_lo = htole32((uint32_t)paddr);
    memcpy(&desc->tbs[0].lo, &addr_lo, sizeof(uint32_t));
    desc->tbs[0].hi_n_len  = htole16(iwm_get_dma_hi_addr(paddr)
                                     | ((hdrlen + paylen) << 4));
    desc->num_tbs = 1;
    
    //    if (paylen > datasz) {
    //        bus_dmamap_sync(sc->sc_dmat, txdata->map, 0,
    //            hdrlen + paylen, BUS_DMASYNC_PREWRITE);
    //    } else {
    //        bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
    //            (char *)(void *)cmd - (char *)(void *)ring->cmd_dma.vaddr,
    //            hdrlen + paylen, BUS_DMASYNC_PREWRITE);
    //    }
    //    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
    //        (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
    //        sizeof (*desc), BUS_DMASYNC_PREWRITE);
    
    /*
     * Wake up the NIC to make sure that the firmware will see the host
     * command - we will let the NIC sleep once all the host commands
     * returned. This needs to be done only on 7000 family NICs.
     */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
        if (ring->queued == 0 && !iwm_nic_lock(sc)) {
            err = EBUSY;
            goto out;
        }
    }
    
    DPRINTFN(2, ("%s: sending command 0x%x\n", __func__, code));

    iwm_update_sched(sc, ring->qid, ring->cur, 0, 0);
    /* Kick command ring. */
    ring->queued++;
    ring->cur = (ring->cur + 1) % IWM_TX_RING_COUNT;
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);
    
    if (!async) {
        err = tsleep_nsec(desc, PCATCH, "iwmcmd", SEC_TO_NSEC(2));
        if (err == 0) {
            /* if hardware is no longer up, return error */
            if (generation != sc->sc_generation) {
                err = ENXIO;
                goto out;
            }
            
            /* Response buffer will be freed in iwm_free_resp(). */
            hcmd->resp_pkt = (struct iwm_rx_packet *)sc->sc_cmd_resp_pkt[idx];
            sc->sc_cmd_resp_pkt[idx] = NULL;
        } else if (generation == sc->sc_generation) {
            ::free(sc->sc_cmd_resp_pkt[idx]);
            sc->sc_cmd_resp_pkt[idx] = NULL;
        }
    }
out:
    splx(s);
    
    return err;
}

int ItlIwm::
iwm_send_cmd_pdu(struct iwm_softc *sc, uint32_t id, uint32_t flags,
                 uint16_t len, const void *data)
{
    struct iwm_host_cmd cmd = {
        .id = id,
        .len = { len, },
        .data = { data, },
        .flags = flags,
    };
    
    return iwm_send_cmd(sc, &cmd);
}

int ItlIwm::
iwm_send_cmd_status(struct iwm_softc *sc, struct iwm_host_cmd *cmd,
                    uint32_t *status)
{
    struct iwm_rx_packet *pkt;
    struct iwm_cmd_response *resp;
    int err, resp_len;
    
    KASSERT((cmd->flags & IWM_CMD_WANT_RESP) == 0, "(cmd->flags & IWM_CMD_WANT_RESP) == 0");
    cmd->flags |= IWM_CMD_WANT_RESP;
    cmd->resp_pkt_len = sizeof(*pkt) + sizeof(*resp);
    
    err = iwm_send_cmd(sc, cmd);
    if (err)
        return err;
    
    pkt = cmd->resp_pkt;
    if (pkt == NULL || (pkt->hdr.flags & IWM_CMD_FAILED_MSK))
        return EIO;
    
    resp_len = iwm_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        iwm_free_resp(sc, cmd);
        return EIO;
    }
    
    resp = (struct iwm_cmd_response *)pkt->data;
    *status = le32toh(resp->status);
    iwm_free_resp(sc, cmd);
    return err;
}

int ItlIwm::
iwm_send_cmd_pdu_status(struct iwm_softc *sc, uint32_t id, uint16_t len,
                        const void *data, uint32_t *status)
{
    struct iwm_host_cmd cmd = {
        .id = id,
        .len = { len, },
        .data = { data, },
    };
    
    return iwm_send_cmd_status(sc, &cmd, status);
}

void ItlIwm::
iwm_free_resp(struct iwm_softc *sc, struct iwm_host_cmd *hcmd)
{
    _KASSERT((hcmd->flags & (IWM_CMD_WANT_RESP)) == IWM_CMD_WANT_RESP);
    ::free(hcmd->resp_pkt);
    hcmd->resp_pkt = NULL;
}

void ItlIwm::
iwm_cmd_done(struct iwm_softc *sc, int qid, int idx, int code)
{
    struct iwm_tx_ring *ring = &sc->txq[sc->cmdqid];
    struct iwm_tx_data *data;
    
    if (qid != sc->cmdqid) {
        return;    /* Not a command ack. */
    }
    
    data = &ring->data[idx];
    
    if (data->m != NULL) {
        //        bus_dmamap_sync(sc->sc_dmat, data->map, 0,
        //            data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
        //        bus_dmamap_unload(sc->sc_dmat, data->map);
        mbuf_freem(data->m);
        data->m = NULL;
    }
    wakeupOn(&ring->desc[idx]);
    
    DPRINTFN(2, ("%s: command 0x%x done\n", __func__, code));
    
    if (ring->queued == 0) {
        XYLog("%s: unexpected firmware response to command 0x%x\n",
              DEVNAME(sc), code);
    } else if (--ring->queued == 0) {
        /*
         * 7000 family NICs are locked while commands are in progress.
         * All commands are now done so we may unlock the NIC again.
         */
        if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
            iwm_nic_unlock(sc);
    }
}
