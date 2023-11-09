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
/*    $OpenBSD: if_iwx.c,v 1.43 2020/08/02 11:11:07 stsp Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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
 ******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
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
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
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
 *
 *****************************************************************************
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
#ifndef _ITLWMX_H
#define _ITLWMX_H
#include <compat.h>
#include <linux/kernel.h>

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kpi_mbuf.h>

#include "if_iwxreg.h"
#include "if_iwxvar.h"
#include <sys/pcireg.h>

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include <HAL/ItlHalService.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>

class ItlIwx : public ItlHalService, ItlDriverInfo, ItlDriverController {
    OSDeclareDefaultStructors(ItlIwx)
    
public:
    
    //kext
    void free() override;
    virtual bool attach(IOPCIDevice *device) override;
    virtual void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    virtual struct ieee80211com *get80211Controller() override;
    
    static bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    static IOReturn _iwx_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    virtual ItlDriverInfo *getDriverInfo() override;
    
    virtual ItlDriverController *getDriverController() override;
    
    //driver info
    virtual const char *getFirmwareVersion() override;
    
    virtual int16_t getBSSNoise() override;
    
    virtual bool is5GBandSupport() override;
    
    virtual int getTxNSS() override;
    
    virtual const char *getFirmwareName() override;
    
    virtual UInt32 supportedFeatures() override;

    virtual const char *getFirmwareCountryCode() override;

    virtual uint32_t getTxQueueSize() override;
    
    //driver controller
    virtual void clearScanningFlags() override;
    
    virtual IOReturn setMulticastList(IOEthernetAddress *addr, int count) override;
    
    void releaseAll();
    void joinSSID(const char *ssid, const char *pwd);
    
    //utils
    static void *mallocarray(size_t, size_t, int, int);
    
//    static void onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context);
    
    uint8_t    iwx_lookup_cmd_ver(struct iwx_softc *, uint8_t, uint8_t);
    uint8_t    iwx_lookup_notif_ver(struct iwx_softc *, uint8_t, uint8_t);
    uint32_t    iwx_lmac_id(struct iwx_softc *, ieee80211_channel *);
    int    iwx_store_cscheme(struct iwx_softc *, uint8_t *, size_t);
    int    iwx_alloc_fw_monitor_block(struct iwx_softc *, uint8_t, uint8_t);
    int    iwx_alloc_fw_monitor(struct iwx_softc *, uint8_t);
    int    iwx_apply_debug_destination(struct iwx_softc *);
    int    iwx_ctxt_info_init(struct iwx_softc *, const struct iwx_fw_sects *);
    int    iwx_ctxt_info_gen3_init(struct iwx_softc *, const struct iwx_fw_sects *);
    void iwx_ctxt_info_free_fw_img(struct iwx_softc *sc);
    int iwx_ctxt_info_alloc_dma(struct iwx_softc *sc,
                                const struct iwx_fw_onesect *sec, struct iwx_dma_info *dram);
    void    iwx_ctxt_info_free_paging(struct iwx_softc *);
    int iwx_get_num_sections(const struct iwx_fw_sects *fws, int start);
    int    iwx_init_fw_sec(struct iwx_softc *, const struct iwx_fw_sects *,
            struct iwx_context_info_dram *);
    void    iwx_fw_version_str(char *, size_t, uint32_t, uint32_t, uint32_t);
    int    iwx_firmware_store_section(struct iwx_softc *, enum iwx_ucode_type,
            uint8_t *, size_t);
    int    iwx_set_default_calib(struct iwx_softc *, const void *);
    void    iwx_fw_info_free(struct iwx_fw_info *);
    void    iwx_pnvm_free(struct iwx_fw_info *);
    int    iwx_read_firmware(struct iwx_softc *);
    int    iwx_read_pnvm(struct iwx_softc *);
    int     iwx_load_pnvm(struct iwx_softc *);
    int     iwx_pnvm_handle_section(struct iwx_softc *, const uint8_t *, size_t);
    uint32_t iwx_read_prph_unlocked(struct iwx_softc *, uint32_t);
    uint32_t iwx_read_prph(struct iwx_softc *, uint32_t);
    uint32_t iwx_read_umac_prph(struct iwx_softc *, uint32_t);
    void    iwx_write_prph(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_write_prph_unlocked(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_write_umac_prph(struct iwx_softc *, uint32_t, uint32_t);
    void iwx_write_prph64(struct iwx_softc *sc, uint64_t addr, uint64_t val);
    int    iwx_read_mem(struct iwx_softc *, uint32_t, void *, int);
    int    iwx_write_mem(struct iwx_softc *, uint32_t, const void *, int);
    int    iwx_write_mem32(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_poll_bit(struct iwx_softc *, int, uint32_t, uint32_t, int);
    int    iwx_nic_lock(struct iwx_softc *);
    void    iwx_nic_assert_locked(struct iwx_softc *);
    void    iwx_nic_unlock(struct iwx_softc *);
    void    iwx_set_bits_mask_prph(struct iwx_softc *, uint32_t, uint32_t,
            uint32_t);
    void    iwx_set_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_clear_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_dma_contig_alloc(bus_dma_tag_t, struct iwx_dma_info *, bus_size_t,
            bus_size_t);
    void    iwx_dma_contig_free(struct iwx_dma_info *);
    int    iwx_alloc_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_disable_rx_dma(struct iwx_softc *);
    void    iwx_reset_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_free_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_tx_ring_init(struct iwx_softc *, struct iwx_tx_ring *, int);
    int    iwx_alloc_tx_ring(struct iwx_softc *, struct iwx_tx_ring *, int);
    void    iwx_reset_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_free_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_enable_rfkill_int(struct iwx_softc *);
    int    iwx_check_rfkill(struct iwx_softc *);
    void    iwx_enable_interrupts(struct iwx_softc *);
    void    iwx_enable_fwload_interrupt(struct iwx_softc *);
    void    iwx_restore_interrupts(struct iwx_softc *);
    void    iwx_disable_interrupts(struct iwx_softc *);
    void    iwx_ict_reset(struct iwx_softc *);
    int    iwx_set_hw_ready(struct iwx_softc *);
    int    iwx_prepare_card_hw(struct iwx_softc *);
    void    iwx_force_power_gating(struct iwx_softc *);
    void    iwx_clear_persistence_bit(struct iwx_softc *);
    void    iwx_apm_config(struct iwx_softc *);
    int    iwx_apm_init(struct iwx_softc *);
    void    iwx_apm_stop(struct iwx_softc *);
    int    iwx_allow_mcast(struct iwx_softc *);
    void    iwx_init_msix_hw(struct iwx_softc *);
    void    iwx_conf_msix_hw(struct iwx_softc *, int);
    int    iwx_start_hw(struct iwx_softc *);
    void    iwx_stop_device(struct iwx_softc *);
    void    iwx_nic_config(struct iwx_softc *);
    int    iwx_nic_rx_init(struct iwx_softc *);
    int    iwx_nic_init(struct iwx_softc *);
    int    iwx_enable_txq(struct iwx_softc *, int, int, int, int);
    int     iwx_tvqm_alloc_txq(struct iwx_softc *, int, int);
    int     iwx_tvqm_enable_txq(struct iwx_softc *, int, int, uint32_t);
    void    iwx_post_alive(struct iwx_softc *);
    int iwx_send_time_event_cmd(struct iwx_softc *sc,
                            const struct iwx_time_event_cmd *cmd);
    void    iwx_protect_session(struct iwx_softc *, struct iwx_node *, uint32_t,
            uint32_t);
    int    iwx_schedule_protect_session(struct iwx_softc *, struct iwx_node *, uint32_t);
    int     iwx_cancel_session_protection(struct iwx_softc *, struct iwx_node *);
    void    iwx_unprotect_session(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_fw_valid_tx_ant(struct iwx_softc *sc);
    uint8_t iwx_fw_valid_rx_ant(struct iwx_softc *sc);
    void    iwx_init_channel_map(struct iwx_softc *, uint16_t *, uint32_t *, int);
    void    iwx_setup_ht_rates(struct iwx_softc *);
    void    iwx_setup_vht_rates(struct iwx_softc *);
    void    iwx_setup_he_rates(struct iwx_softc *);
    int    iwx_mimo_enabled(struct iwx_softc *);
    static void    iwx_mac_ctxt_task(void *);
    static void    iwx_chan_ctxt_task(void *);
    static void    iwx_updateprot(struct ieee80211com *);
    static void    iwx_updateslot(struct ieee80211com *);
    static void    iwx_updateedca(struct ieee80211com *);
    static void    iwx_updatedtim(struct ieee80211com *);
    void    iwx_init_reorder_buffer(struct iwx_reorder_buffer *, uint16_t,
            uint16_t);
    void    iwx_clear_reorder_buffer(struct iwx_softc *, struct iwx_rxba_data *);
    static int    iwx_ampdu_rx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ampdu_rx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_rx_ba_session_expired(void *);
    static void    iwx_reorder_timer_expired(void *);
    static void    iwx_update_chw(struct ieee80211com *);
    void    iwx_sta_rx_agg(struct iwx_softc *, struct ieee80211_node *, uint8_t,
                           uint16_t, uint16_t, int, int);
    static int    iwx_ampdu_tx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ampdu_tx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ba_task(void *);

    int    iwx_set_mac_addr_from_csr(struct iwx_softc *, struct iwx_nvm_data *);
    int    iwx_is_valid_mac_addr(const uint8_t *);
    int    iwx_nvm_get(struct iwx_softc *);
    int    iwx_load_firmware(struct iwx_softc *);
    void   iwx_set_ltr(struct iwx_softc *);
    int    iwx_start_fw(struct iwx_softc *);
    int    iwx_send_tx_ant_cfg(struct iwx_softc *, uint8_t);
    int    iwx_send_phy_cfg_cmd(struct iwx_softc *);
    int    iwx_load_ucode_wait_alive(struct iwx_softc *);
    int    iwx_send_dqa_cmd(struct iwx_softc *);
    int    iwx_run_init_mvm_ucode(struct iwx_softc *, int);
    int    iwx_config_ltr(struct iwx_softc *);
    void    iwx_update_rx_desc(struct iwx_softc *, struct iwx_rx_ring *, int);
    int    iwx_rx_addbuf(struct iwx_softc *, int, int);
    int    iwx_rxmq_get_signal_strength(struct iwx_softc *, struct iwx_rx_mpdu_desc *);
    void    iwx_rx_rx_phy_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_get_noise(const uint8_t *);
    int    iwx_rx_hwdecrypt(struct iwx_softc *, mbuf_t, uint32_t,
            struct ieee80211_rxinfo *);
    int    iwx_ccmp_decap(struct iwx_softc *, mbuf_t,
                          struct ieee80211_node *, struct ieee80211_rxinfo *);
    void    iwx_rx_frame(struct iwx_softc *, mbuf_t, int, uint32_t, int, int,
           uint32_t, struct ieee80211_rxinfo *, struct mbuf_list *);
    void iwx_rx_mpdu_mq(struct iwx_softc *sc, mbuf_t m, void *pktdata,
                        size_t maxlen, struct mbuf_list *ml);
    void    iwx_rx_tx_cmd_single(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_tx_data *);
    void iwx_txd_done(struct iwx_softc *sc, struct iwx_tx_data *txd);
    void iwx_clear_oactive(struct iwx_softc *sc, struct iwx_tx_ring *ring);
    void iwx_ampdu_txq_advance(struct iwx_softc *sc, struct iwx_tx_ring *ring, int idx);
    void iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data);
    void    iwx_rx_tx_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    void    iwx_rx_bmiss(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_binding_cmd(struct iwx_softc *, struct iwx_node *, uint32_t);
    int    iwx_phy_ctxt_cmd_uhb(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
                                uint8_t, uint32_t, uint32_t);
    int    iwx_phy_ctxt_cmd_v3(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
                                uint8_t, uint32_t, uint32_t);
    int    iwx_phy_ctxt_cmd(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
            uint8_t, uint32_t, uint32_t);
    int    iwx_send_cmd(struct iwx_softc *, struct iwx_host_cmd *);
    int    iwx_send_cmd_pdu(struct iwx_softc *, uint32_t, uint32_t, uint16_t,
            const void *);
    int    iwx_send_cmd_status(struct iwx_softc *, struct iwx_host_cmd *,
            uint32_t *);
    int    iwx_send_cmd_pdu_status(struct iwx_softc *, uint32_t, uint16_t,
            const void *, uint32_t *);
    void    iwx_free_resp(struct iwx_softc *, struct iwx_host_cmd *);
    void    iwx_cmd_done(struct iwx_softc *, int, int, int);
    const struct iwx_rate *iwx_tx_fill_cmd(struct iwx_softc *, struct iwx_node *,
            struct ieee80211_frame *, uint32_t *, uint32_t *);
    uint32_t iwx_get_tx_ant(struct iwx_softc *sc, struct ieee80211_node *ni,
                            const struct iwx_rate *rinfo, int type, struct ieee80211_frame *wh);
    void    iwx_toggle_tx_ant(struct iwx_softc *sc, uint8_t *ant);
    void    iwx_tx_update_byte_tbl(struct iwx_softc *, struct iwx_tx_ring *, int, uint16_t, uint16_t);
    int    iwx_tx(struct iwx_softc *, mbuf_t, struct ieee80211_node *, int);
    int    iwx_flush_sta_tids(struct iwx_softc *, int, uint16_t);
    int    iwx_flush_sta(struct iwx_softc *, struct iwx_node *);
    int    iwx_drain_sta(struct iwx_softc *sc, struct iwx_node *, int);
    int    iwx_beacon_filter_send_cmd(struct iwx_softc *,
            struct iwx_beacon_filter_cmd *);
    int    iwx_update_beacon_abort(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_power_build_cmd(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_power_cmd *);
    int    iwx_power_mac_update_mode(struct iwx_softc *, struct iwx_node *);
    int    iwx_power_update_device(struct iwx_softc *);
    int    iwx_enable_beacon_filter(struct iwx_softc *, struct iwx_node *);
    int    iwx_disable_beacon_filter(struct iwx_softc *);
    int    iwx_add_sta_cmd(struct iwx_softc *, struct iwx_node *, int);
    int    iwx_add_aux_sta(struct iwx_softc *);
    int    iwx_rm_sta_cmd(struct iwx_softc *, struct iwx_node *);
    int    iwx_rm_sta(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_umac_scan_fill_channels(struct iwx_softc *sc,
                                struct iwx_scan_channel_cfg_umac *chan, int n_ssids, int bgscan);
    int iwx_fill_probe_req_v1(struct iwx_softc *sc, struct iwx_scan_probe_req_v1 *preq1);
    int    iwx_fill_probe_req(struct iwx_softc *, struct iwx_scan_probe_req *);
    int    iwx_config_umac_scan(struct iwx_softc *);
    int    iwx_config_legacy_umac_scan(struct iwx_softc *);
    int iwx_umac_scan_size(struct iwx_softc *sc);
    struct iwx_scan_umac_chan_param *iwx_get_scan_req_umac_chan_param(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    void *iwx_get_scan_req_umac_data(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    int    iwx_umac_scan(struct iwx_softc *, int);
    int    iwx_umac_scan_v12(struct iwx_softc *, int);
    int    iwx_umac_scan_v14(struct iwx_softc *, int);
    void    iwx_mcc_update(struct iwx_softc *, struct iwx_mcc_chub_notif *);
    uint8_t    iwx_ridx2rate(struct ieee80211_rateset *, int);
    int    iwx_rval2ridx(int);
    int    iwx_rate2idx(int);
    void    iwx_ack_rates(struct iwx_softc *, struct iwx_node *, int *, int *);
    void    iwx_mac_ctxt_cmd_common(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_ctx_cmd *, uint32_t);
    void    iwx_mac_ctxt_cmd_fill_sta(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_data_sta *, int);
    int    iwx_mac_ctxt_cmd(struct iwx_softc *, struct iwx_node *, uint32_t, int);
    int    iwx_clear_statistics(struct iwx_softc *);
    int    iwx_update_quotas(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_add_task(struct iwx_softc *, struct taskq *, struct task *);
    void    iwx_del_task(struct iwx_softc *, struct taskq *, struct task *);
    int    iwx_scan(struct iwx_softc *);
    static int    iwx_bgscan(struct ieee80211com *);
    int    iwx_umac_scan_abort(struct iwx_softc *);
    int    iwx_scan_abort(struct iwx_softc *);
    int    iwx_rs_rval2idx(uint8_t);
    uint16_t iwx_rs_ht_rates(struct iwx_softc *, struct ieee80211_node *, int);
    uint16_t iwx_rs_fw_get_config_flags(struct iwx_softc *sc);
    int    iwx_rs_init(struct iwx_softc *, struct iwx_node *, bool update);
    void iwx_rs_update(struct iwx_softc *sc, struct iwx_tlc_update_notif *notif);
    int    iwx_enable_mgmt_queue(struct iwx_softc *);
    int    iwx_phy_ctxt_update(struct iwx_softc *, struct iwx_phy_ctxt *,
                               struct ieee80211_channel *, uint8_t, uint8_t, uint32_t);
    int    iwx_auth(struct iwx_softc *);
    int    iwx_deauth(struct iwx_softc *);
    int    iwx_run(struct iwx_softc *);
    int    iwx_run_stop(struct iwx_softc *);
    static struct ieee80211_node *iwx_node_alloc(struct ieee80211com *);
    static int    iwx_set_key(struct ieee80211com *, struct ieee80211_node *,
           struct ieee80211_key *);
    static void    iwx_delete_key(struct ieee80211com *,
           struct ieee80211_node *, struct ieee80211_key *);
    int    iwx_media_change(struct _ifnet *);
    static void    iwx_newstate_task(void *);
    static int    iwx_newstate(struct ieee80211com *, enum ieee80211_state, int);
    void    iwx_endscan(struct iwx_softc *);
    void    iwx_fill_sf_command(struct iwx_softc *, struct iwx_sf_cfg_cmd *,
            struct ieee80211_node *);
    int    iwx_sf_config(struct iwx_softc *, int);
    int    iwx_send_bt_init_conf(struct iwx_softc *);
    int    iwx_send_soc_conf(struct iwx_softc *);
    int    iwx_send_update_mcc_cmd(struct iwx_softc *, const char *);
    int    iwx_send_temp_report_ths_cmd(struct iwx_softc *);
    int    iwx_init_hw(struct iwx_softc *);
    int    iwx_init(struct _ifnet *);
    static void    iwx_start(struct _ifnet *);
    void    iwx_stop(struct _ifnet *);
    static void    iwx_watchdog(struct _ifnet *);
    static int    iwx_ioctl(struct _ifnet *, u_long, caddr_t);
    const char *iwx_desc_lookup(uint32_t);
    void    iwx_nic_error(struct iwx_softc *);
    void    iwx_nic_umac_error(struct iwx_softc *);
    void    iwx_flip_address(uint8_t *);
    int    iwx_detect_duplicate(struct iwx_softc *, mbuf_t,
            struct iwx_rx_mpdu_desc *, struct ieee80211_rxinfo *);
    int    iwx_is_sn_less(uint16_t, uint16_t, uint16_t);
    void    iwx_release_frames(struct iwx_softc *, struct ieee80211_node *,
            struct iwx_rxba_data *, struct iwx_reorder_buffer *, uint16_t,
            struct mbuf_list *);
    int    iwx_oldsn_workaround(struct iwx_softc *, struct ieee80211_node *,
            int, struct iwx_reorder_buffer *, uint32_t, uint32_t);
    int    iwx_rx_reorder(struct iwx_softc *, mbuf_t, int,
            struct iwx_rx_mpdu_desc *, int, int, uint32_t,
            struct ieee80211_rxinfo *, struct mbuf_list *);
    int    iwx_rx_pkt_valid(struct iwx_rx_packet *);
    void    iwx_rx_pkt(struct iwx_softc *, struct iwx_rx_data *,
            struct mbuf_list *);
    void    iwx_notif_intr(struct iwx_softc *);
    static int    iwx_intr(OSObject *object, IOInterruptEventSource* sender, int count);
    static int    iwx_intr_msix(OSObject *object, IOInterruptEventSource* sender, int count);
    static int    iwx_match(IOPCIDevice *);
    int    iwx_preinit(struct iwx_softc *);
    void    iwx_attach_hook(struct device *);
    bool    iwx_attach(struct iwx_softc *, struct pci_attach_args *);
    static void    iwx_init_task(void *);
    int    iwx_activate(struct iwx_softc *, int);
    int    iwx_resume(struct iwx_softc *);
    
public:
    IOInterruptEventSource* fInterrupt;
    struct pci_attach_args pci;
    struct iwx_softc com;
};

#endif
