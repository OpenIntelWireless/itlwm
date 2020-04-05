//
//  power.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

#define IWM_POWER_KEEP_ALIVE_PERIOD_SEC    25

int itlwm::
iwm_beacon_filter_send_cmd(struct iwm_softc *sc,
                           struct iwm_beacon_filter_cmd *cmd)
{
    return iwm_send_cmd_pdu(sc, IWM_REPLY_BEACON_FILTERING_CMD,
                            0, sizeof(struct iwm_beacon_filter_cmd), cmd);
}

void itlwm::
iwm_beacon_filter_set_cqm_params(struct iwm_softc *sc, struct iwm_node *in,
                                 struct iwm_beacon_filter_cmd *cmd)
{
    cmd->ba_enable_beacon_abort = htole32(sc->sc_bf.ba_enabled);
}

int itlwm::
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

void itlwm::
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

int itlwm::
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

int itlwm::
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

int itlwm::
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

int itlwm::
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

int itlwm::
iwm_add_sta_cmd(struct iwm_softc *sc, struct iwm_node *in, int update)
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
    } else if (!update) {
        int ac;
        for (ac = 0; ac < EDCA_NUM_AC; ac++) {
            int qid = ac;
            if (isset(sc->sc_enabled_capa,
                      IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
                qid += IWM_DQA_MIN_MGMT_QUEUE;
            add_sta_cmd.tfd_queue_msk |= htole32(1 << qid);
        }
        IEEE80211_ADDR_COPY(&add_sta_cmd.addr, in->in_ni.ni_bssid);
    }
    add_sta_cmd.add_modify = update ? 1 : 0;
    add_sta_cmd.station_flags_msk
    |= htole32(IWM_STA_FLG_FAT_EN_MSK | IWM_STA_FLG_MIMO_EN_MSK);
    add_sta_cmd.tid_disable_tx = htole16(0xffff);
    if (update)
        add_sta_cmd.modify_mask |= (IWM_STA_MODIFY_TID_DISABLE_TX);
    
    if (in->in_ni.ni_flags & IEEE80211_NODE_HT) {
        add_sta_cmd.station_flags_msk
        |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_MSK |
                   IWM_STA_FLG_AGG_MPDU_DENS_MSK);
        
        add_sta_cmd.station_flags
        |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_64K);
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
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS)
        err = EIO;
    
    return err;
}

int itlwm::
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
                             IWM_TX_FIFO_MCAST);
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

int itlwm::
iwm_rm_sta_cmd(struct iwm_softc *sc, struct iwm_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_rm_sta_cmd rm_sta_cmd;
    int err;
    
    if ((sc->sc_flags & IWM_FLAG_STA_ACTIVE) == 0)
        panic("sta already removed");
    
    memset(&rm_sta_cmd, 0, sizeof(rm_sta_cmd));
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        rm_sta_cmd.sta_id = IWM_MONITOR_STA_ID;
    else
        rm_sta_cmd.sta_id = IWM_STATION_ID;
    
    err = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm_sta_cmd),
                           &rm_sta_cmd);
    
    return err;
}
