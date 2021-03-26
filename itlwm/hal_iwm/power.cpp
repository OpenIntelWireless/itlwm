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

#define IWM_POWER_KEEP_ALIVE_PERIOD_SEC    25

int ItlIwm::
iwm_beacon_filter_send_cmd(struct iwm_softc *sc,
                           struct iwm_beacon_filter_cmd *cmd)
{
    return iwm_send_cmd_pdu(sc, IWM_REPLY_BEACON_FILTERING_CMD,
                            0, sizeof(struct iwm_beacon_filter_cmd), cmd);
}

void ItlIwm::
iwm_beacon_filter_set_cqm_params(struct iwm_softc *sc, struct iwm_node *in,
                                 struct iwm_beacon_filter_cmd *cmd)
{
    cmd->ba_enable_beacon_abort = htole32(sc->sc_bf.ba_enabled);
}

int ItlIwm::
iwm_update_beacon_abort(struct iwm_softc *sc, struct iwm_node *in, int enable)
{
    struct iwm_beacon_filter_cmd cmd = {
        IWM_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
        .ba_enable_beacon_abort = htole32(enable),
    };
    
    if (!sc->sc_bf.bf_enabled)
        return 0;
    
    sc->sc_bf.ba_enabled = enable;
    iwm_beacon_filter_set_cqm_params(sc, in, &cmd);
    return iwm_beacon_filter_send_cmd(sc, &cmd);
}

void ItlIwm::
iwm_power_build_cmd(struct iwm_softc *sc, struct iwm_node *in,
                    struct iwm_mac_power_cmd *cmd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int dtim_period, dtim_msec, keep_alive;
    
    cmd->id_and_color = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id,
                                                        in->in_color));
    if (ni->ni_dtimperiod)
        dtim_period = ni->ni_dtimperiod;
    else
        dtim_period = 1;
    
    /*
     * Regardless of power management state the driver must set
     * keep alive period. FW will use it for sending keep alive NDPs
     * immediately after association. Check that keep alive period
     * is at least 3 * DTIM.
     */
    dtim_msec = dtim_period * ni->ni_intval;
    keep_alive = MAX(3 * dtim_msec, 1000 * IWM_POWER_KEEP_ALIVE_PERIOD_SEC);
    keep_alive = roundup(keep_alive, 1000) / 1000;
    cmd->keep_alive_seconds = htole16(keep_alive);
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        cmd->flags = htole16(IWM_POWER_FLAGS_POWER_SAVE_ENA_MSK);
}

int ItlIwm::
iwm_power_mac_update_mode(struct iwm_softc *sc, struct iwm_node *in)
{
    int err;
    int ba_enable;
    struct iwm_mac_power_cmd cmd;
    
    memset(&cmd, 0, sizeof(cmd));
    
    iwm_power_build_cmd(sc, in, &cmd);
    
    err = iwm_send_cmd_pdu(sc, IWM_MAC_PM_POWER_TABLE, 0,
                           sizeof(cmd), &cmd);
    if (err != 0)
        return err;
    
    ba_enable = !!(cmd.flags &
                   htole16(IWM_POWER_FLAGS_POWER_MANAGEMENT_ENA_MSK));
    return iwm_update_beacon_abort(sc, in, ba_enable);
}

int ItlIwm::
iwm_power_update_device(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_device_power_cmd cmd = { };
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        cmd.flags = htole16(IWM_DEVICE_POWER_FLAGS_POWER_SAVE_ENA_MSK);
    
    return iwm_send_cmd_pdu(sc,
                            IWM_POWER_TABLE_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwm::
iwm_enable_beacon_filter(struct iwm_softc *sc, struct iwm_node *in)
{
    struct iwm_beacon_filter_cmd cmd = {
        IWM_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
    };
    int err;
    
    iwm_beacon_filter_set_cqm_params(sc, in, &cmd);
    err = iwm_beacon_filter_send_cmd(sc, &cmd);
    
    if (err == 0)
        sc->sc_bf.bf_enabled = 1;
    
    return err;
}

int ItlIwm::
iwm_disable_beacon_filter(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_beacon_filter_cmd cmd;
    int err;
    
    memset(&cmd, 0, sizeof(cmd));
    
    err = iwm_beacon_filter_send_cmd(sc, &cmd);
    if (err == 0)
        sc->sc_bf.bf_enabled = 0;
    
    return err;
}

int ItlIwm::
iwm_add_sta_cmd(struct iwm_softc *sc, struct iwm_node *in, int update, unsigned int flags)
{
    struct iwm_add_sta_cmd add_sta_cmd;
    int err;
    uint32_t status;
    size_t cmdsize;
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (!update && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        panic("STA already added");
    
    memset(&add_sta_cmd, 0, sizeof(add_sta_cmd));
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        add_sta_cmd.sta_id = IWM_MONITOR_STA_ID;
    else
        add_sta_cmd.sta_id = IWM_STATION_ID;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE)) {
        if (ic->ic_opmode == IEEE80211_M_MONITOR)
            add_sta_cmd.station_type = IWM_STA_GENERAL_PURPOSE;
        else
            add_sta_cmd.station_type = IWM_STA_LINK;
    }
    add_sta_cmd.mac_id_n_color
    = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        int qid;
        IEEE80211_ADDR_COPY(&add_sta_cmd.addr, etheranyaddr);
        if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
            qid = IWM_DQA_INJECT_MONITOR_QUEUE;
        else
            qid = IWM_AUX_QUEUE;
        add_sta_cmd.tfd_queue_msk |= htole32(1 << qid);
    } else if (!update || (flags & IWM_STA_MODIFY_QUEUES)) {
        if (!update) {
            int ac;
            sc->agg_queue_mask = 0;
            sc->agg_tid_disable = 0xffff;
            for (ac = 0; ac < EDCA_NUM_AC; ac++) {
                int qid = ac;
                if (isset(sc->sc_enabled_capa,
                          IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
                    qid += IWM_DQA_MIN_MGMT_QUEUE;
                sc->agg_queue_mask |= htole32(1 << qid);
            }
        }
        add_sta_cmd.tfd_queue_msk = sc->agg_queue_mask;
        IEEE80211_ADDR_COPY(&add_sta_cmd.addr, in->in_ni.ni_bssid);
    }
    add_sta_cmd.add_modify = update ? 1 : 0;
    add_sta_cmd.station_flags_msk
    |= htole32(IWM_STA_FLG_FAT_EN_MSK | IWM_STA_FLG_MIMO_EN_MSK);
    add_sta_cmd.tid_disable_tx = htole16(sc->agg_tid_disable);
    if (update)
        add_sta_cmd.modify_mask |= (IWM_STA_MODIFY_TID_DISABLE_TX);
    
    if (in->in_ni.ni_flags & IEEE80211_NODE_HT) {
        XYLog("%s line=%d\n", __FUNCTION__, __LINE__);
        add_sta_cmd.station_flags_msk
        |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_MSK |
                   IWM_STA_FLG_AGG_MPDU_DENS_MSK);
        if (iwm_mimo_enabled(sc)) {
            if (in->in_ni.ni_rxmcs[1] != 0) {
                add_sta_cmd.station_flags |=
                htole32(IWM_STA_FLG_MIMO_EN_MIMO2);
            }
            if (in->in_ni.ni_rxmcs[2] != 0) {
                add_sta_cmd.station_flags |=
                htole32(IWM_STA_FLG_MIMO_EN_MIMO3);
            }
        }
        
        add_sta_cmd.station_flags
        |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_64K);
        add_sta_cmd.station_flags
        |= htole32(IWM_STA_FLG_FAT_EN_20MHZ);
        if (in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_40 && ic->ic_state >= IEEE80211_S_ASSOC) {
            add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_FAT_EN_40MHZ);
        }
        switch (ic->ic_ampdu_params & IEEE80211_AMPDU_PARAM_SS) {
            case IEEE80211_AMPDU_PARAM_SS_2:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_2US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_4:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_4US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_8:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_8US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_16:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_16US);
                break;
            default:
                break;
        }
    }
    
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(add_sta_cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize,
                                  &add_sta_cmd, &status);
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS) {
        err = EIO;
        XYLog("%s failed\n", __FUNCTION__);
    }
    
    return err;
}

int ItlIwm::
iwm_add_aux_sta(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_add_sta_cmd cmd;
    int err, qid;
    uint32_t status;
    size_t cmdsize;
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT)) {
        qid = IWM_DQA_AUX_QUEUE;
        err = iwm_enable_txq(sc, IWM_AUX_STA_ID, qid,
                             IWM_TX_FIFO_MCAST, 0, 0, 0);
    } else {
        qid = IWM_AUX_QUEUE;
        err = iwm_enable_ac_txq(sc, qid, IWM_TX_FIFO_MCAST);
    }
    if (err)
        return err;
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.sta_id = IWM_AUX_STA_ID;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmd.station_type = IWM_STA_AUX_ACTIVITY;
    cmd.mac_id_n_color =
    htole32(IWM_FW_CMD_ID_AND_COLOR(IWM_MAC_INDEX_AUX, 0));
    cmd.tfd_queue_msk = htole32(1 << qid);
    cmd.tid_disable_tx = htole16(0xffff);
    
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize, &cmd,
                                  &status);
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS)
        err = EIO;
    
    return err;
}

int ItlIwm::
iwm_drain_sta(struct iwm_softc *sc, struct iwm_node *in, bool drain)
{
    struct iwm_add_sta_cmd cmd = {};
    int err;
    uint32_t status;
    size_t cmdsize;
    
    cmd.mac_id_n_color = cpu_to_le32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.sta_id = IWM_STATION_ID;
    cmd.add_modify = IWM_STA_MODE_MODIFY;
    cmd.station_flags = drain ? cpu_to_le32(IWM_STA_FLG_DRAIN_FLOW) : 0;
    cmd.station_flags_msk = cpu_to_le32(IWM_STA_FLG_DRAIN_FLOW);
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA,
                      cmdsize,
                      &cmd, &status);
    return err;
}

int ItlIwm::
iwm_rm_sta_cmd(struct iwm_softc *sc, struct iwm_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_rm_sta_cmd rm_sta_cmd;
    int err;
    uint8_t qid;
    
    if ((sc->sc_flags & IWM_FLAG_STA_ACTIVE) == 0)
        panic("sta already removed");
    
    if (ic->ic_opmode == IEEE80211_M_STA) {
        err = iwm_drain_sta(sc, in, true);
        if (err) {
            XYLog("%s can not drain sta(TRUE)\n", __FUNCTION__);
            goto done;
        }
        err = iwm_flush_tx_path(sc, sc->agg_queue_mask);
        if (err) {
            XYLog("%s can not flush sta tx path\n", __FUNCTION__);
            goto done;
        }
        err = iwm_drain_sta(sc, in, false);
        if (err) {
            XYLog("%s can not drain sta(FALSE)\n", __FUNCTION__);
            goto done;
        }
        for (qid = IWM_FIRST_AGG_TX_QUEUE; qid <= IWM_LAST_AGG_TX_QUEUE; qid++) {
            if (sc->agg_queue_mask & (1 << qid)) {
                iwm_disable_txq(sc, qid, 0, 0);
            }
        }
    }
    memset(&rm_sta_cmd, 0, sizeof(rm_sta_cmd));
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        rm_sta_cmd.sta_id = IWM_MONITOR_STA_ID;
    else
        rm_sta_cmd.sta_id = IWM_STATION_ID;
    
    err = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm_sta_cmd),
                           &rm_sta_cmd);
done:
    sc->agg_queue_mask = 0;
    sc->agg_tid_disable = 0xffff;
    
    return err;
}
