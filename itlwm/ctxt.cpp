//
//  ctxt.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

void itlwm::
iwm_phy_ctxt_cmd_hdr(struct iwm_softc *sc, struct iwm_phy_ctxt *ctxt,
    struct iwm_phy_context_cmd *cmd, uint32_t action, uint32_t apply_time)
{
    memset(cmd, 0, sizeof(struct iwm_phy_context_cmd));
    
        cmd->id_and_color = htole32(IWM_FW_CMD_ID_AND_COLOR(ctxt->id,
            ctxt->color));
        cmd->action = htole32(action);
        cmd->apply_time = htole32(apply_time);
}

void itlwm::
iwm_phy_ctxt_cmd_data(struct iwm_softc *sc, struct iwm_phy_context_cmd *cmd,
    struct ieee80211_channel *chan, uint8_t chains_static,
    uint8_t chains_dynamic)
{
    struct ieee80211com *ic = &sc->sc_ic;
        uint8_t active_cnt, idle_cnt;
    
        cmd->ci.band = IEEE80211_IS_CHAN_2GHZ(chan) ?
            IWM_PHY_BAND_24 : IWM_PHY_BAND_5;
        cmd->ci.channel = ieee80211_chan2ieee(ic, chan);
        cmd->ci.width = IWM_PHY_VHT_CHANNEL_MODE20;
        cmd->ci.ctrl_pos = IWM_PHY_VHT_CTRL_POS_1_BELOW;
    
        /* Set rx the chains */
        idle_cnt = chains_static;
        active_cnt = chains_dynamic;
    
        cmd->rxchain_info = htole32(iwm_fw_valid_rx_ant(sc) <<
                        IWM_PHY_RX_CHAIN_VALID_POS);
        cmd->rxchain_info |= htole32(idle_cnt << IWM_PHY_RX_CHAIN_CNT_POS);
        cmd->rxchain_info |= htole32(active_cnt <<
            IWM_PHY_RX_CHAIN_MIMO_CNT_POS);
    
        cmd->txchain_info = htole32(iwm_fw_valid_tx_ant(sc));
}

int itlwm::
iwm_phy_ctxt_cmd(struct iwm_softc *sc, struct iwm_phy_ctxt *ctxt,
    uint8_t chains_static, uint8_t chains_dynamic, uint32_t action,
    uint32_t apply_time)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_phy_context_cmd cmd;
    
        iwm_phy_ctxt_cmd_hdr(sc, ctxt, &cmd, action, apply_time);
    
        iwm_phy_ctxt_cmd_data(sc, &cmd, ctxt->channel,
            chains_static, chains_dynamic);
    
        return iwm_send_cmd_pdu(sc, IWM_PHY_CONTEXT_CMD, 0,
            sizeof(struct iwm_phy_context_cmd), &cmd);
}
