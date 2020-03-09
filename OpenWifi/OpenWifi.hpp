/* add your code here */
#include "compat.h"
#include "itlhdr.h"
#include "kernel.h"

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/IOWorkLoop.h>
#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/assert.h>
#include <IOKit/IODataQueue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOInterruptEventSource.h>

#include "apple80211.h"

typedef enum {
    MEDIUM_TYPE_NONE = 0,
    MEDIUM_TYPE_AUTO,
    MEDIUM_TYPE_1MBIT,
    MEDIUM_TYPE_2MBIT,
    MEDIUM_TYPE_5MBIT,
    MEDIUM_TYPE_11MBIT,
    MEDIUM_TYPE_54MBIT,
    MEDIUM_TYPE_INVALID
} mediumType_t;

#define RELEASE(x) if(x){(x)->release();(x)=NULL;}

class itlwm : public IO80211Controller {
    OSDeclareDefaultStructors(itlwm)
    
public:
    bool init(OSDictionary* parameters) APPLE_KEXT_OVERRIDE;
    void free() APPLE_KEXT_OVERRIDE;
    bool start(IOService* provider) APPLE_KEXT_OVERRIDE;
    void stop(IOService* provider) APPLE_KEXT_OVERRIDE;
    IOService* probe(IOService* provider, SInt32* score) override;
    
    SInt32 apple80211Request(unsigned int request_type, int request_number, IO80211Interface* interface, void* data) override;
    UInt32 outputPacket (mbuf_t m, void* param) override;
    IOReturn getMaxPacketSize(UInt32* maxSize) const;
    const OSString* newVendorString() const;
    const OSString* newModelString() const;
    const OSString* newRevisionString() const;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    bool configureInterface(IONetworkInterface *netif) override;
    IO80211Interface* getNetworkInterface() override;
    IOReturn getHardwareAddressForInterface(IO80211Interface* netif, IOEthernetAddress* addr) override;
    IOReturn getHardwareAddress(IOEthernetAddress* addr) override;
    IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    SInt32 monitorModeSetEnabled(IO80211Interface* interface, bool enabled, UInt32 dlt) override;
    
    bool createWorkLoop() override;
    IOWorkLoop* getWorkLoop() const override;
    
    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    int tsleep_nsec(void *ident, int priority, const char *wmesg, int timo);
    void wakeupOn(void* ident);
    bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    
    //utils
    static void *malloc(vm_size_t len, int type, int how);
    static void free(void* addr);
    static void free(void *addr, int type, vm_size_t len);
    
    //fw
    uint8_t iwm_fw_valid_tx_ant(struct iwm_softc *sc);
    uint8_t iwm_fw_valid_rx_ant(struct iwm_softc *sc);
    static void onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context);
    
    //scan
    uint8_t iwm_umac_scan_fill_channels(struct iwm_softc *sc,
                                        struct iwm_scan_channel_cfg_umac *chan, int n_ssids, int bgscan);
    
    int    iwm_is_mimo_ht_plcp(uint8_t);
    int    iwm_is_mimo_mcs(int);
    int    iwm_store_cscheme(struct iwm_softc *, uint8_t *, size_t);
    int    iwm_firmware_store_section(struct iwm_softc *, enum iwm_ucode_type,
            uint8_t *, size_t);
    int    iwm_set_default_calib(struct iwm_softc *, const void *);
    void    iwm_fw_info_free(struct iwm_fw_info *);
    int    iwm_read_firmware(struct iwm_softc *, enum iwm_ucode_type);
    uint32_t iwm_read_prph(struct iwm_softc *, uint32_t);
    void    iwm_write_prph(struct iwm_softc *, uint32_t, uint32_t);
    int    iwm_read_mem(struct iwm_softc *, uint32_t, void *, int);
    int    iwm_write_mem(struct iwm_softc *, uint32_t, const void *, int);
    int    iwm_write_mem32(struct iwm_softc *, uint32_t, uint32_t);
    int    iwm_poll_bit(struct iwm_softc *, int, uint32_t, uint32_t, int);
    int    iwm_nic_lock(struct iwm_softc *);
    void    iwm_nic_assert_locked(struct iwm_softc *);
    void    iwm_nic_unlock(struct iwm_softc *);
    void    iwm_set_bits_mask_prph(struct iwm_softc *, uint32_t, uint32_t,
            uint32_t);
    void    iwm_set_bits_prph(struct iwm_softc *, uint32_t, uint32_t);
    void    iwm_clear_bits_prph(struct iwm_softc *, uint32_t, uint32_t);
    int    iwm_dma_contig_alloc(bus_dma_tag_t, struct iwm_dma_info *, void**, bus_size_t,
            bus_size_t);
    void    iwm_dma_contig_free(struct iwm_dma_info *);
    int    iwm_alloc_rx_ring(struct iwm_softc *, struct iwm_rx_ring *);
    void    iwm_disable_rx_dma(struct iwm_softc *);
    void    iwm_reset_rx_ring(struct iwm_softc *, struct iwm_rx_ring *);
    void    iwm_free_rx_ring(struct iwm_softc *, struct iwm_rx_ring *);
    int    iwm_alloc_tx_ring(struct iwm_softc *, struct iwm_tx_ring *, int);
    void    iwm_reset_tx_ring(struct iwm_softc *, struct iwm_tx_ring *);
    void    iwm_free_tx_ring(struct iwm_softc *, struct iwm_tx_ring *);
    void    iwm_enable_rfkill_int(struct iwm_softc *);
    int    iwm_check_rfkill(struct iwm_softc *);
    void    iwm_enable_interrupts(struct iwm_softc *);
    void    iwm_restore_interrupts(struct iwm_softc *);
    void    iwm_disable_interrupts(struct iwm_softc *);
    void    iwm_ict_reset(struct iwm_softc *);
    int    iwm_set_hw_ready(struct iwm_softc *);
    int    iwm_prepare_card_hw(struct iwm_softc *);
    void    iwm_apm_config(struct iwm_softc *);
    int    iwm_apm_init(struct iwm_softc *);
    void    iwm_apm_stop(struct iwm_softc *);
    int    iwm_allow_mcast(struct iwm_softc *);
    int    iwm_start_hw(struct iwm_softc *);
    void    iwm_stop_device(struct iwm_softc *);
    void    iwm_nic_config(struct iwm_softc *);
    int    iwm_nic_rx_init(struct iwm_softc *);
    int    iwm_nic_tx_init(struct iwm_softc *);
    int    iwm_nic_init(struct iwm_softc *);
    int    iwm_enable_txq(struct iwm_softc *, int, int, int);
    int    iwm_post_alive(struct iwm_softc *);
    struct iwm_phy_db_entry *iwm_phy_db_get_section(struct iwm_softc *, uint16_t,
            uint16_t);
    int    iwm_phy_db_set_section(struct iwm_softc *,
            struct iwm_calib_res_notif_phy_db *);
    int    iwm_is_valid_channel(uint16_t);
    uint8_t    iwm_ch_id_to_ch_index(uint16_t);
    uint16_t iwm_channel_id_to_papd(uint16_t);
    uint16_t iwm_channel_id_to_txp(struct iwm_softc *, uint16_t);
    int    iwm_phy_db_get_section_data(struct iwm_softc *, uint32_t, uint8_t **,
            uint16_t *, uint16_t);
    int    iwm_send_phy_db_cmd(struct iwm_softc *, uint16_t, uint16_t, void *);
    int    iwm_phy_db_send_all_channel_groups(struct iwm_softc *, uint16_t,
            uint8_t);
    int    iwm_send_phy_db_data(struct iwm_softc *);
    void    iwm_te_v2_to_v1(const struct iwm_time_event_cmd_v2 *,
            struct iwm_time_event_cmd_v1 *);
    int    iwm_send_time_event_cmd(struct iwm_softc *,
            const struct iwm_time_event_cmd_v2 *);
    void    iwm_protect_session(struct iwm_softc *, struct iwm_node *, uint32_t,
            uint32_t);
    void    iwm_unprotect_session(struct iwm_softc *, struct iwm_node *);
    int    iwm_nvm_read_chunk(struct iwm_softc *, uint16_t, uint16_t, uint16_t,
            uint8_t *, uint16_t *);
    int    iwm_nvm_read_section(struct iwm_softc *, uint16_t, uint8_t *,
            uint16_t *, size_t);
    void    iwm_init_channel_map(struct iwm_softc *, const uint16_t * const,
            const uint8_t *nvm_channels, size_t nchan);
    void    iwm_setup_ht_rates(struct iwm_softc *);
    static void    iwm_htprot_task(void *);
    static void    iwm_update_htprot(struct ieee80211com *, struct ieee80211_node *);
    static int    iwm_ampdu_rx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwm_ampdu_rx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    void    iwm_sta_rx_agg(struct iwm_softc *, struct ieee80211_node *, uint8_t,
            uint16_t, int);
    #ifdef notyet
    int    iwm_ampdu_tx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    void    iwm_ampdu_tx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    #endif
    static void    iwm_ba_task(void *);

    int    iwm_parse_nvm_data(struct iwm_softc *, const uint16_t *,
            const uint16_t *, const uint16_t *,
            const uint16_t *, const uint16_t *,
            const uint16_t *);
    void    iwm_set_hw_address_8000(struct iwm_softc *, struct iwm_nvm_data *,
            const uint16_t *, const uint16_t *);
    int    iwm_parse_nvm_sections(struct iwm_softc *, struct iwm_nvm_section *);
    int    iwm_nvm_init(struct iwm_softc *);
    int    iwm_firmware_load_sect(struct iwm_softc *, uint32_t, const uint8_t *,
            uint32_t);
    int    iwm_firmware_load_chunk(struct iwm_softc *, uint32_t, const uint8_t *,
            uint32_t);
    int    iwm_load_firmware_7000(struct iwm_softc *, enum iwm_ucode_type);
    int    iwm_load_cpu_sections_8000(struct iwm_softc *, struct iwm_fw_sects *,
            int , int *);
    int    iwm_load_firmware_8000(struct iwm_softc *, enum iwm_ucode_type);
    int    iwm_load_firmware(struct iwm_softc *, enum iwm_ucode_type);
    int    iwm_start_fw(struct iwm_softc *, enum iwm_ucode_type);
    int    iwm_send_tx_ant_cfg(struct iwm_softc *, uint8_t);
    int    iwm_send_phy_cfg_cmd(struct iwm_softc *);
    int    iwm_load_ucode_wait_alive(struct iwm_softc *, enum iwm_ucode_type);
    int    iwm_run_init_mvm_ucode(struct iwm_softc *, int);
    int    iwm_rx_addbuf(struct iwm_softc *, int, int);
    int    iwm_calc_rssi(struct iwm_softc *, struct iwm_rx_phy_info *);
    int    iwm_get_signal_strength(struct iwm_softc *, struct iwm_rx_phy_info *);
    void    iwm_rx_rx_phy_cmd(struct iwm_softc *, struct iwm_rx_packet *,
            struct iwm_rx_data *);
    int    iwm_get_noise(const struct iwm_statistics_rx_non_phy *);
    void    iwm_rx_rx_mpdu(struct iwm_softc *, struct iwm_rx_packet *,
            struct iwm_rx_data *, struct mbuf_list *);
    void    iwm_enable_ht_cck_fallback(struct iwm_softc *, struct iwm_node *);
    void    iwm_rx_tx_cmd_single(struct iwm_softc *, struct iwm_rx_packet *,
            struct iwm_node *);
    void    iwm_rx_tx_cmd(struct iwm_softc *, struct iwm_rx_packet *,
            struct iwm_rx_data *);
    void    iwm_rx_bmiss(struct iwm_softc *, struct iwm_rx_packet *,
            struct iwm_rx_data *);
    int    iwm_binding_cmd(struct iwm_softc *, struct iwm_node *, uint32_t);
    void    iwm_phy_ctxt_cmd_hdr(struct iwm_softc *, struct iwm_phy_ctxt *,
            struct iwm_phy_context_cmd *, uint32_t, uint32_t);
    void    iwm_phy_ctxt_cmd_data(struct iwm_softc *, struct iwm_phy_context_cmd *,
            struct ieee80211_channel *, uint8_t, uint8_t);
    int    iwm_phy_ctxt_cmd(struct iwm_softc *, struct iwm_phy_ctxt *, uint8_t,
            uint8_t, uint32_t, uint32_t);
    int    iwm_send_cmd(struct iwm_softc *, struct iwm_host_cmd *);
    int    iwm_send_cmd_pdu(struct iwm_softc *, uint32_t, uint32_t, uint16_t,
            const void *);
    int    iwm_send_cmd_status(struct iwm_softc *, struct iwm_host_cmd *,
            uint32_t *);
    int    iwm_send_cmd_pdu_status(struct iwm_softc *, uint32_t, uint16_t,
            const void *, uint32_t *);
    void    iwm_free_resp(struct iwm_softc *, struct iwm_host_cmd *);
    void    iwm_cmd_done(struct iwm_softc *, int, int, int);
    void    iwm_update_sched(struct iwm_softc *, int, int, uint8_t, uint16_t);
    const struct iwm_rate *iwm_tx_fill_cmd(struct iwm_softc *, struct iwm_node *,
            struct ieee80211_frame *, struct iwm_tx_cmd *);
    int    iwm_tx(struct iwm_softc *, mbuf_t, struct ieee80211_node *, int);
    int    iwm_flush_tx_path(struct iwm_softc *, int);
    void    iwm_led_enable(struct iwm_softc *);
    void    iwm_led_disable(struct iwm_softc *);
    int    iwm_led_is_enabled(struct iwm_softc *);
    static void    iwm_led_blink_timeout(void *);
    void    iwm_led_blink_start(struct iwm_softc *);
    void    iwm_led_blink_stop(struct iwm_softc *);
    int    iwm_beacon_filter_send_cmd(struct iwm_softc *,
            struct iwm_beacon_filter_cmd *);
    void    iwm_beacon_filter_set_cqm_params(struct iwm_softc *, struct iwm_node *,
            struct iwm_beacon_filter_cmd *);
    int    iwm_update_beacon_abort(struct iwm_softc *, struct iwm_node *, int);
    void    iwm_power_build_cmd(struct iwm_softc *, struct iwm_node *,
            struct iwm_mac_power_cmd *);
    int    iwm_power_mac_update_mode(struct iwm_softc *, struct iwm_node *);
    int    iwm_power_update_device(struct iwm_softc *);
    int    iwm_enable_beacon_filter(struct iwm_softc *, struct iwm_node *);
    int    iwm_disable_beacon_filter(struct iwm_softc *);
    int    iwm_add_sta_cmd(struct iwm_softc *, struct iwm_node *, int);
    int    iwm_add_aux_sta(struct iwm_softc *);
    int    iwm_rm_sta_cmd(struct iwm_softc *, struct iwm_node *);
    uint16_t iwm_scan_rx_chain(struct iwm_softc *);
    uint32_t iwm_scan_rate_n_flags(struct iwm_softc *, int, int);
    uint8_t    iwm_lmac_scan_fill_channels(struct iwm_softc *,
            struct iwm_scan_channel_cfg_lmac *, int, int);
    int    iwm_fill_probe_req(struct iwm_softc *, struct iwm_scan_probe_req *);
    int    iwm_lmac_scan(struct iwm_softc *, int);
    int    iwm_config_umac_scan(struct iwm_softc *);
    int    iwm_umac_scan(struct iwm_softc *, int);
    uint8_t    iwm_ridx2rate(struct ieee80211_rateset *, int);
    int    iwm_rval2ridx(int);
    void    iwm_ack_rates(struct iwm_softc *, struct iwm_node *, int *, int *);
    void    iwm_mac_ctxt_cmd_common(struct iwm_softc *, struct iwm_node *,
            struct iwm_mac_ctx_cmd *, uint32_t, int);
    void    iwm_mac_ctxt_cmd_fill_sta(struct iwm_softc *, struct iwm_node *,
            struct iwm_mac_data_sta *, int);
    int    iwm_mac_ctxt_cmd(struct iwm_softc *, struct iwm_node *, uint32_t, int);
    int    iwm_update_quotas(struct iwm_softc *, struct iwm_node *, int);
    void    iwm_add_task(struct iwm_softc *, struct taskq *, struct task *);
    void    iwm_del_task(struct iwm_softc *, struct taskq *, struct task *);
    int    iwm_scan(struct iwm_softc *);
    static int    iwm_bgscan(struct ieee80211com *);
    int    iwm_umac_scan_abort(struct iwm_softc *);
    int    iwm_lmac_scan_abort(struct iwm_softc *);
    int    iwm_scan_abort(struct iwm_softc *);
    int    iwm_auth(struct iwm_softc *);
    int    iwm_deauth(struct iwm_softc *);
    int    iwm_assoc(struct iwm_softc *);
    int    iwm_disassoc(struct iwm_softc *);
    int    iwm_run(struct iwm_softc *);
    int    iwm_run_stop(struct iwm_softc *);
    static struct ieee80211_node *iwm_node_alloc(struct ieee80211com *);
    static void    iwm_calib_timeout(void *);
    int    iwm_media_change(struct ifnet *);
    static void    iwm_newstate_task(void *);
    static int    iwm_newstate(struct ieee80211com *, enum ieee80211_state, int);
    void    iwm_endscan(struct iwm_softc *);
    void    iwm_fill_sf_command(struct iwm_softc *, struct iwm_sf_cfg_cmd *,
            struct ieee80211_node *);
    int    iwm_sf_config(struct iwm_softc *, int);
    int    iwm_send_bt_init_conf(struct iwm_softc *);
    int    iwm_send_update_mcc_cmd(struct iwm_softc *, const char *);
    void    iwm_tt_tx_backoff(struct iwm_softc *, uint32_t);
    int    iwm_init_hw(struct iwm_softc *);
    int    iwm_init(struct ifnet *);
    static void    iwm_start(struct ifnet *);
    void    iwm_stop(struct ifnet *);
    static void    iwm_watchdog(struct ifnet *);
    static int    iwm_ioctl(struct ifnet *, u_long, caddr_t);
    #ifdef IWM_DEBUG
    const char *iwm_desc_lookup(uint32_t);
    void    iwm_nic_error(struct iwm_softc *);
    void    iwm_nic_umac_error(struct iwm_softc *);
    #endif
    void    iwm_notif_intr(struct iwm_softc *);
    int    iwm_intr(OSObject *object, IOInterruptEventSource* sender, int count);
    int    iwm_match(IOPCIDevice *);
    int    iwm_preinit(struct iwm_softc *);
    void    iwm_attach_hook(struct device *);
    bool    iwm_attach(struct iwm_softc *, struct pci_attach_args *);
    static void    iwm_init_task(void *);
    int    iwm_activate(struct device *, int);
    int    iwm_resume(struct iwm_softc *);
    
protected:
    IO80211Interface* getInterface();
    
private:
    // 1 - SSID
    IOReturn getSSID(IO80211Interface* interface, struct apple80211_ssid_data* sd);
    IOReturn setSSID(IO80211Interface* interface, struct apple80211_ssid_data* sd);
    // 2 - AUTH_TYPE
    IOReturn getAUTH_TYPE(IO80211Interface* interface, struct apple80211_authtype_data* ad);
    // 4 - CHANNEL
    IOReturn getCHANNEL(IO80211Interface* interface, struct apple80211_channel_data* cd);
    // 7 - TXPOWER
    IOReturn getTXPOWER(IO80211Interface* interface, struct apple80211_txpower_data* txd);
    // 8 - RATE
    IOReturn getRATE(IO80211Interface* interface, struct apple80211_rate_data* rd);
    // 9 - BSSID
    IOReturn getBSSID(IO80211Interface* interface, struct apple80211_bssid_data* bd);
    // 10 - SCAN_REQ
    IOReturn setSCAN_REQ(IO80211Interface* interface, struct apple80211_scan_data* sd);
    // 11 - SCAN_RESULT
    IOReturn getSCAN_RESULT(IO80211Interface* interface, apple80211_scan_result* *sr);
    // 12 - CARD_CAPABILITIES
    IOReturn getCARD_CAPABILITIES(IO80211Interface* interface, struct apple80211_capability_data* cd);
    // 13 - STATE
    IOReturn getSTATE(IO80211Interface* interface, struct apple80211_state_data* sd);
    IOReturn setSTATE(IO80211Interface* interface, struct apple80211_state_data* sd);
    // 14 - PHY_MODE
    IOReturn getPHY_MODE(IO80211Interface* interface, struct apple80211_phymode_data* pd);
    // 15 - OP_MODE
    IOReturn getOP_MODE(IO80211Interface* interface, struct apple80211_opmode_data* od);
    // 16 - RSSI
    IOReturn getRSSI(IO80211Interface* interface, struct apple80211_rssi_data* rd);
    // 17 - NOISE
    IOReturn getNOISE(IO80211Interface* interface,struct apple80211_noise_data* nd);
    // 18 - INT_MIT
    IOReturn getINT_MIT(IO80211Interface* interface, struct apple80211_intmit_data* imd);
    // 19 - POWER
    IOReturn getPOWER(IO80211Interface* interface, struct apple80211_power_data* pd);
    IOReturn setPOWER(IO80211Interface* interface, struct apple80211_power_data* pd);
    // 20 - ASSOCIATE
    IOReturn setASSOCIATE(IO80211Interface* interface,struct apple80211_assoc_data* ad);
    // 27 - SUPPORTED_CHANNELS
    IOReturn getSUPPORTED_CHANNELS(IO80211Interface* interface, struct apple80211_sup_channel_data* ad);
    // 28 - LOCALE
    IOReturn getLOCALE(IO80211Interface* interface, struct apple80211_locale_data* ld);
    // 37 - TX_ANTENNA
    IOReturn getTX_ANTENNA(IO80211Interface* interface, apple80211_antenna_data* ad);
    // 39 - ANTENNA_DIVERSITY
    IOReturn getANTENNA_DIVERSITY(IO80211Interface* interface, apple80211_antenna_data* ad);
    // 43 - DRIVER_VERSION
    IOReturn getDRIVER_VERSION(IO80211Interface* interface, struct apple80211_version_data* hv);
    // 44 - HARDWARE_VERSION
    IOReturn getHARDWARE_VERSION(IO80211Interface* interface, struct apple80211_version_data* hv);
    // 51 - COUNTRY_CODE
    IOReturn getCOUNTRY_CODE(IO80211Interface* interface, struct apple80211_country_code_data* cd);
    // 57 - MCS
    IOReturn getMCS(IO80211Interface* interface, struct apple80211_mcs_data* md);
    IOReturn getROAM_THRESH(IO80211Interface* interface, struct apple80211_roam_threshold_data* md);
    IOReturn getRADIO_INFO(IO80211Interface* interface, struct apple80211_radio_info_data* md);
    
    void setCurrentState(enum apple80211_state state) {
        this->state = state;
    };
    
    enum apple80211_state getCurrentState() {
        return this->state;
    };
    
    inline void ReleaseAll() {
        RELEASE(fOutputQueue);
        RELEASE(fCommandGate);
        RELEASE(fWorkloop);
        RELEASE(mediumDict);
        RELEASE(fWorkloop);
        RELEASE(fPciDevice);
    }
    
    bool addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);
    
    IO80211WorkLoop* fWorkloop;
    IO80211Interface* fInterface;
    IOGatedOutputQueue* fOutputQueue;
    IOCommandGate* fCommandGate;
    IOPCIDevice* fPciDevice;
    
    OSDictionary* mediumDict;
    IONetworkMedium* mediumTable[MEDIUM_TYPE_INVALID];
    
    IOInterruptEventSource* fInterrupt;
    struct pci_attach_args pci;
    struct iwm_softc com;
    
    IOLock *fwLoadLock;
    
    ieee80211_node* fNextNodeToSend;
    bool fScanResultWrapping;
    
    enum apple80211_state state;
    int power_state;
};

struct ResourceCallbackContext
{
    itlwm* context;
    OSData* resource;
};
