/*
 *  wps_eap.h
 *  Family
 *
 *  Created by Pete on 6/20/06.
 *  Copyright 2006 Apple Computer, Inc. All rights reserved.
 *
 */

#include <sys/types.h>
#include <net/ethernet.h>
//#include "eap_defs.h"

#ifndef WPS_EAP_H
#define WPS_EAP_H

#define WPS_HANDSHAKE_TIMEOUT    120 /* seconds */
#define WPS_RETRANSMIT_TIMEOUT    5
#define WPS_MAX_RETRIES            3

#define WPS_IDENTITY_STR                "WFA-SimpleConfig-Enrollee-1-0"
#define WPS_IDENTITY_STR_LEN            29
#define WPS_PERSONALIZATION_STRING        "Wi-Fi Easy and Secure Key Derivation"
#define WPS_PERSONALIZATION_STRING_LEN    ( sizeof( WPS_PERSONALIZATION_STRING ) - 1 )
#define WPS_KDF_KEY_BITS                640

#define WPS_DISPLAY_PIN_LEN        8

#define EAP_TYPE_ID            1
#define WPS_EAP_METHOD_TYPE    254

#define WPS_VENDOR_ID_BYTES 0x00, 0x37, 0x2A
#define WPS_VENDOR_TYPE        0x00000001

#define WPS_OP_START        0x01
#define WPS_OP_ACK            0x02
#define WPS_OP_NACK            0x03
#define WPS_OP_MSG            0x04
#define WPS_OP_DONE            0x05

#define WPS_FLAG_MF            0x01    /* more fragments */
#define WPS_FLAG_LF            0x02    /* length field in use */

#define WPS_MAX_MSG_LEN UINT16_MAX    /* max frag len, my limit */

#define PACKED __attribute__((packed))

struct wps_eap_hdr
{
    u_int8_t    code;
    u_int8_t    identifier;
    u_int16_t    length;
    u_int8_t    type;
    u_int8_t    vendor_id[3];
    u_int32_t    vendor_type;
    u_int8_t    op_code;
    u_int8_t    flags;
    u_int16_t    msg_length;
    //    u_int8_t    msg[1];        /* data follows */
}PACKED;
#define WPS_EAP_HDR_LEN( _whdr ) ( ( _whdr->flags & WPS_FLAG_LF ) ? sizeof( struct wps_eap_hdr ) : sizeof( struct wps_eap_hdr ) - sizeof( u_int16_t ) )

// Messages elements

#define BUF_SIZE_64_BITS    8
#define BUF_SIZE_128_BITS   16
#define BUF_SIZE_160_BITS   20
#define BUF_SIZE_256_BITS   32
#define BUF_SIZE_512_BITS   64
#define BUF_SIZE_1024_BITS  128
#define BUF_SIZE_1536_BITS  192

struct wps_msg_elem_hdr
{
    u_int16_t    elem_id;
    u_int16_t    elem_len;
}PACKED;

#define WPS_ELEM_SET_HEADER( elem, id, len ) (elem)->hdr.elem_id = htons( id ); (elem)->hdr.elem_len = htons( len )

struct wps_dev_type
{
    u_int16_t    category;
    u_int8_t    oui[4];
    u_int16_t    sub_category;
}PACKED;

#define WIFI_DEV_TYPE_OUI_BYTES    0x00, 0x50, 0xf2, 0x04

#define DEFINE_WPS_ELEMENT( name, param )    typedef struct {                    \
struct wps_msg_elem_hdr hdr;    \
param;                            \
}PACKED name


#define WPS_VERSION 0x10
DEFINE_WPS_ELEMENT( wps_elem_ap_channel_t, u_int16_t channel );
DEFINE_WPS_ELEMENT( wps_elem_assoc_state_t, u_int16_t assoc_state );
DEFINE_WPS_ELEMENT( wps_elem_auth_type_t, u_int16_t auth_type );
DEFINE_WPS_ELEMENT( wps_elem_auth_type_flags_t, u_int16_t auth_flags );
#define AUTHENTICATOR_MSG_SIZE ( sizeof( struct wps_msg_elem_hdr ) + 8 )
DEFINE_WPS_ELEMENT( wps_elem_authenticator_t, u_int8_t authenticator[8] );
DEFINE_WPS_ELEMENT( wps_elem_config_methods_t, u_int16_t config_methods );
DEFINE_WPS_ELEMENT( wps_elem_config_error_t, u_int16_t error );
DEFINE_WPS_ELEMENT( wps_elem_confirm_url4_t, u_int16_t url4[1] ); // <= 64B
DEFINE_WPS_ELEMENT( wps_elem_confirm_url6_t, u_int16_t url6[1] ); // <= 76B
DEFINE_WPS_ELEMENT( wps_elem_conn_type_t, u_int8_t conn_type );
DEFINE_WPS_ELEMENT( wps_elem_conn_type_flags_t, u_int8_t conn_type_flags );
DEFINE_WPS_ELEMENT( wps_elem_credential_t, u_int8_t cred[1] );    // <= ???
DEFINE_WPS_ELEMENT( wps_elem_dev_name_t, u_int8_t dev_name[1] ); // <= 32B
DEFINE_WPS_ELEMENT( wps_elem_dev_pw_id_t, u_int16_t dev_pw_id );
DEFINE_WPS_ELEMENT( wps_elem_e_hash1_t, u_int8_t e_hash1[BUF_SIZE_256_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_e_hash2_t, u_int8_t e_hash2[BUF_SIZE_256_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_e_snonce1_t, u_int8_t e_snonce1[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_e_snonce2_t, u_int8_t e_snonce2[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_ecrypt_settings_t, u_int8_t settings[1] );    // no limit defined
DEFINE_WPS_ELEMENT( wps_elem_encrypt_type_t, u_int16_t encrypt_type );
DEFINE_WPS_ELEMENT( wps_elem_encrypt_type_flags_t, u_int16_t encrypt_type_flags );
DEFINE_WPS_ELEMENT( wps_elem_enrl_nonce_t, u_int8_t nonce[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_feature_id_t, u_int32_t feature_id );
DEFINE_WPS_ELEMENT( wps_elem_identity_t, u_int8_t identity[1] ); // <= 80
// identity proof?
DEFINE_WPS_ELEMENT( wps_elem_iv_t, u_int8_t iv[BUF_SIZE_256_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_key_wrap_authenticator_t, u_int8_t key_wrap_authenticator[8] );
DEFINE_WPS_ELEMENT( wps_elem_key_id_t, u_int8_t key_id[16] );
DEFINE_WPS_ELEMENT( wps_elem_mac_addr_t, u_int8_t mac[ETHER_ADDR_LEN] );
DEFINE_WPS_ELEMENT( wps_elem_manufacturer_t, u_int8_t manufacturer[1] ); // <= 64
DEFINE_WPS_ELEMENT( wps_elem_msg_type_t, u_int8_t msg_type  );
DEFINE_WPS_ELEMENT( wps_elem_model_name_t, u_int8_t model_name[1] ); // <= 32B
DEFINE_WPS_ELEMENT( wps_elem_model_number_t, u_int8_t model_number[1] ); // <= 32B
DEFINE_WPS_ELEMENT( wps_elem_network_index_t, u_int8_t network_index );
DEFINE_WPS_ELEMENT( wps_elem_network_key_t, u_int8_t network_key[1] ); // <= 64B
DEFINE_WPS_ELEMENT( wps_elem_network_key_index_t, u_int8_t network_key_index );
DEFINE_WPS_ELEMENT( wps_elem_new_dev_name_t, u_int8_t new_dev_name[1] ); // <= 32B
DEFINE_WPS_ELEMENT( wps_elem_new_pw_t, u_int8_t new_pw[1] ); // <= 64
// oob device password?
DEFINE_WPS_ELEMENT( wps_elem_os_version_t, u_int32_t os_version );
DEFINE_WPS_ELEMENT( wps_elem_power_level_t, u_int8_t power_level );
DEFINE_WPS_ELEMENT( wps_elem_psk_current_t, u_int8_t psk_current );
DEFINE_WPS_ELEMENT( wps_elem_psk_max_t, u_int8_t psk_max );
DEFINE_WPS_ELEMENT( wps_elem_public_key_t, u_int8_t key[BUF_SIZE_1536_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_radio_enabled_t, u_int8_t radio_enabled ); // bool?
DEFINE_WPS_ELEMENT( wps_elem_reboot_t, u_int8_t reboot ); // bool?
DEFINE_WPS_ELEMENT( wps_elem_reg_current_t, u_int8_t reg_current );
DEFINE_WPS_ELEMENT( wps_elem_reg_established_t, u_int8_t reg_established ); // bool?
DEFINE_WPS_ELEMENT( wps_elem_reg_list_t, u_int8_t reg_list[1] ); // <= 512B
DEFINE_WPS_ELEMENT( wps_elem_reg_max_t, u_int8_t reg_max );
DEFINE_WPS_ELEMENT( wps_elem_reg_nonce_t, u_int8_t nonce[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_req_type_t, u_int8_t req_type );
DEFINE_WPS_ELEMENT( wps_elem_resp_type_t, u_int8_t resp_type );
DEFINE_WPS_ELEMENT( wps_elem_rf_band_t, u_int8_t rf_band );
DEFINE_WPS_ELEMENT( wps_elem_r_hash1, u_int8_t r_hash1[BUF_SIZE_256_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_r_hash2, u_int8_t r_hash2[BUF_SIZE_256_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_r_snonce1, u_int8_t r_snonce1[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_r_snonce2, u_int8_t r_snonce2[BUF_SIZE_128_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_selected_reg_t, u_int8_t selected_reg );    // bool?
DEFINE_WPS_ELEMENT( wps_elem_serial_number_t, u_int8_t serial_number[1] ); // <= 32B
DEFINE_WPS_ELEMENT( wps_elem_simple_config_state_t, u_int8_t simple_config_state );
DEFINE_WPS_ELEMENT( wps_elem_ssid_t, u_int8_t ssid[32] );
DEFINE_WPS_ELEMENT( wps_elem_total_networks_t, u_int8_t total_networks );
DEFINE_WPS_ELEMENT( wps_elem_uuid_e_t, u_int8_t uuid_e[16] );
DEFINE_WPS_ELEMENT( wps_elem_uuid_r_t, u_int8_t uuid_r[16] );
DEFINE_WPS_ELEMENT( wps_elem_vendor_ext_t, u_int8_t vendor_ext[1] ); // <= 1024
DEFINE_WPS_ELEMENT( wps_elem_version_t, u_int8_t version  ); // int?
DEFINE_WPS_ELEMENT( wps_elem_x_509_cert_req_t, u_int8_t cert_req[1] );    // limit?
DEFINE_WPS_ELEMENT( wps_elem_x_509_cert_t, u_int8_t cert[1] );    // limit?
DEFINE_WPS_ELEMENT( wps_elem_eap_id_t, u_int8_t eap_id[1] ); // <= 64
DEFINE_WPS_ELEMENT( wps_elem_msg_counter_t, u_int8_t msg_counter[8] );
DEFINE_WPS_ELEMENT( wps_elem_public_key_hash_t, u_int8_t public_key_hash[BUF_SIZE_160_BITS] );
DEFINE_WPS_ELEMENT( wps_elem_rekey_key_t, u_int8_t rekey_key[32] );
DEFINE_WPS_ELEMENT( wps_elem_key_lifetime_t, u_int32_t key_lifetime );
DEFINE_WPS_ELEMENT( wps_elem_permitted_config_methods_t, u_int16_t permitted_config_methods );
DEFINE_WPS_ELEMENT( wps_elem_sel_reg_config_methods_t, u_int8_t sel_reg_config_methods );
DEFINE_WPS_ELEMENT( wps_elem_primary_dev_type_t, struct wps_dev_type prime_dev_type );
DEFINE_WPS_ELEMENT( wps_elem_secondary_dev_type_list_t, u_int8_t secondary_dev_type_list[1] ); // <= 128B
DEFINE_WPS_ELEMENT( wps_elem_portable_dev_t, u_int8_t portable_dev );    // bool?
DEFINE_WPS_ELEMENT( wps_elem_ap_setup_locked_t, u_int8_t ap_setup_locked ); // bool?
DEFINE_WPS_ELEMENT( wps_elem_app_list_t, u_int8_t app_list[1] ); // <= 512B
DEFINE_WPS_ELEMENT( wps_elem_eap_type_t, u_int8_t eap_type[1] ); // <= 8B

#define WPS_NEXT_ELEMENT( cast, cur_elm, len ) (cast)( (UInt8 *)(cur_elm) + sizeof( struct wps_msg_elem_hdr ) + ntohs( cur_elm->hdr.elem_len ) );    \
len+=( sizeof( struct wps_msg_elem_hdr ) + ntohs( cur_elm->hdr.elem_len ) )
#define WPS_NEXT_ELEMENT_IE( cast, cur_elm, len ) (cast)( (UInt8 *)(cur_elm) + sizeof( struct wps_msg_elem_hdr ) + ntohs( cur_elm->hdr.elem_len ) );    \
len-=( sizeof( struct wps_msg_elem_hdr ) + ntohs( cur_elm->hdr.elem_len ) );
#define WPS_ELEMENT_IS( elem, id ) ( ntohs( elem->hdr.elem_id ) == id )
#define WPS_ELEMENT_LEN_VAR( elem )    ( sizeof( struct wps_msg_elem_hdr ) + ntohs( elem->hdr.elem_len ) )
#define WPS_ELEMENT_LEN_FIXED( fixed ) ( sizeof( struct wps_msg_elem_hdr ) + sizeof( fixed ) )
#define WPS_ELEMENT_PARAM_LEN( elem ) ( ntohs( elem->hdr.elem_len ) )

// Messages
#define WPS_MBUF_GET_MSG_PTR( m, type ) (type *)( (UInt8 *)mbuf_data( m ) + sizeof( struct ether_header ) + sizeof( struct wps_eap_hdr ) )

struct wps_msg_nack
{
    wps_elem_version_t        version;
    wps_elem_msg_type_t        msg_type;
    wps_elem_enrl_nonce_t    enrl_nonce;
    wps_elem_reg_nonce_t    reg_nonce;
    wps_elem_config_error_t error;
}PACKED;

struct wps_msg_ack
{
    wps_elem_version_t        version;
    wps_elem_msg_type_t        msg_type;
    wps_elem_enrl_nonce_t    enrl_nonce;
    wps_elem_reg_nonce_t    reg_nonce;
}PACKED;

struct wps_msg_done
{
    wps_elem_version_t        version;
    wps_elem_msg_type_t        msg_type;
};

// From RFC 3748 section 4.1 for identity
struct wps_identity_msg
{
    u_int8_t    code;
    u_int8_t    id;
    u_int16_t    length;
    u_int8_t    type;
    //    u_int8_t    type_data[1];    /* data follows */
}__attribute__((packed));

#define WPS_EAP_TYPE_IDENTITY    1

// Data Element Definitions
#define WPS_ID_AP_CHANNEL         0x1001
#define WPS_ID_ASSOC_STATE        0x1002
#define WPS_ID_AUTH_TYPE          0x1003
#define WPS_ID_AUTH_TYPE_FLAGS    0x1004
#define WPS_ID_AUTHENTICATOR      0x1005
#define WPS_ID_CONFIG_METHODS     0x1008
#define WPS_ID_CONFIG_ERROR       0x1009
#define WPS_ID_CONF_URL4          0x100A
#define WPS_ID_CONF_URL6          0x100B
#define WPS_ID_CONN_TYPE          0x100C
#define WPS_ID_CONN_TYPE_FLAGS    0x100D
#define WPS_ID_CREDENTIAL         0x100E
#define WPS_ID_DEVICE_NAME        0x1011
#define WPS_ID_DEVICE_PWD_ID      0x1012
#define WPS_ID_E_HASH1            0x1014
#define WPS_ID_E_HASH2            0x1015
#define WPS_ID_E_SNONCE1          0x1016
#define WPS_ID_E_SNONCE2          0x1017
#define WPS_ID_ENCR_SETTINGS      0x1018
#define WPS_ID_ENCR_TYPE          0x100F
#define WPS_ID_ENCR_TYPE_FLAGS    0x1010
#define WPS_ID_ENROLLEE_NONCE     0x101A
#define WPS_ID_FEATURE_ID         0x101B
#define WPS_ID_IDENTITY           0x101C
#define WPS_ID_IDENTITY_PROOF     0x101D
#define WPS_ID_INIT_VECTOR        0x104B //this becomes 0x1060 later
//#define WPS_ID_KEY_WRAP_AUTH      WPS_ID_AUTHENTICATOR //this becomes 0x101E later
#define WPS_ID_KEY_WRAP_AUTH      0x101E // HH changed for MS beta 2 testing
#define WPS_ID_KEY_IDENTIFIER     0x101F
#define WPS_ID_MAC_ADDR           0x1020
#define WPS_ID_MANUFACTURER       0x1021
#define WPS_ID_MSG_TYPE           0x1022
#define WPS_ID_MODEL_NAME         0x1023
#define WPS_ID_MODEL_NUMBER       0x1024
#define WPS_ID_NW_INDEX           0x1026
#define WPS_ID_NW_KEY             0x1027
#define WPS_ID_NW_KEY_INDEX       0x1028
#define WPS_ID_NEW_DEVICE_NAME    0x1029
#define WPS_ID_NEW_PWD            0x102A
#define WPS_ID_OOB_DEV_PWD        0x102C
#define WPS_ID_OS_VERSION         0x102D
#define WPS_ID_POWER_LEVEL        0x102F
#define WPS_ID_PSK_CURRENT        0x1030
#define WPS_ID_PSK_MAX            0x1031
#define WPS_ID_PUBLIC_KEY         0x1032
#define WPS_ID_RADIO_ENABLED      0x1033
#define WPS_ID_REBOOT             0x1034
#define WPS_ID_REGISTRAR_CURRENT  0x1035
#define WPS_ID_REGISTRAR_ESTBLSHD 0x1036
#define WPS_ID_REGISTRAR_LIST     0x1037
#define WPS_ID_REGISTRAR_MAX      0x1038
#define WPS_ID_REGISTRAR_NONCE    0x1039
#define WPS_ID_REQ_TYPE           0x103A
#define WPS_ID_RESP_TYPE          0x103B
#define WPS_ID_RF_BAND            0x103C
#define WPS_ID_R_HASH1            0x103D
#define WPS_ID_R_HASH2            0x103E
#define WPS_ID_R_SNONCE1          0x103F
#define WPS_ID_R_SNONCE2          0x1040
#define WPS_ID_SEL_REGISTRAR      0x1041
#define WPS_ID_SERIAL_NUM         0x1042
#define WPS_ID_SC_STATE           0x1044
#define WPS_ID_SSID               0x1045
#define WPS_ID_TOT_NETWORKS       0x1046
#define WPS_ID_UUID_E             0x1047
#define WPS_ID_UUID_R             0x1048
#define WPS_ID_VENDOR_EXT         0x1049
#define WPS_ID_VERSION            0x104A
#define WPS_ID_X509_CERT_REQ      0x104B
#define WPS_ID_X509_CERT          0x104C
#define WPS_ID_EAP_IDENTITY       0x104D
#define WPS_ID_MSG_COUNTER        0x104E
#define WPS_ID_PUBKEY_HASH        0x104F
#define WPS_ID_REKEY_KEY          0x1050
#define WPS_ID_KEY_LIFETIME       0x1051
#define WPS_ID_PERM_CFG_METHODS   0x1052
#define WPS_ID_SEL_REG_CFG_METHODS_ORIGINAL 0x0153    // This was the original val in the spec, we must support both
#define WPS_ID_SEL_REG_CFG_METHODS 0x1053
#define WPS_ID_PRIM_DEV_TYPE      0x1054
#define WPS_ID_SEC_DEV_TYPE_LIST  0x1055
#define WPS_ID_PORTABLE_DEVICE    0x1056
#define WPS_ID_AP_SETUP_LOCKED    0x1057
#define WPS_ID_APP_LIST           0x1058
#define WPS_ID_EAP_TYPE           0x1059

// Association states
#define WPS_ASSOC_NOT_ASSOCIATED  0
#define WPS_ASSOC_CONN_SUCCESS    1
#define WPS_ASSOC_CONFIG_FAIL     2
#define WPS_ASSOC_ASSOC_FAIL      3
#define WPS_ASSOC_IP_FAIL         4

// Authentication types
#define WPS_AUTHTYPE_OPEN        0x0001
#define WPS_AUTHTYPE_WPAPSK      0x0002
#define WPS_AUTHTYPE_SHARED      0x0004
#define WPS_AUTHTYPE_WPA         0x0008
#define WPS_AUTHTYPE_WPA2        0x0010
#define WPS_AUTHTYPE_WPA2PSK     0x0020

// Config methods
#define WPS_CONFMET_USBA            0x0001
#define WPS_CONFMET_ETHERNET        0x0002
#define WPS_CONFMET_LABEL           0x0004
#define WPS_CONFMET_DISPLAY         0x0008
#define WPS_CONFMET_EXT_NFC_TOK     0x0010
#define WPS_CONFMET_INT_NFC_TOK     0x0020
#define WPS_CONFMET_NFC_INTF        0x0040
#define WPS_CONFMET_PBC             0x0080
#define WPS_CONFMET_KEYPAD          0x0100

// WPS error messages
#define WPS_ERROR_NO_ERROR                0
#define WPS_ERROR_OOB_INT_READ_ERR        1
#define WPS_ERROR_DECRYPT_CRC_FAIL        2
#define WPS_ERROR_CHAN24_NOT_SUPP         3
#define WPS_ERROR_CHAN50_NOT_SUPP         4
#define WPS_ERROR_SIGNAL_WEAK             5
#define WPS_ERROR_NW_AUTH_FAIL            6
#define WPS_ERROR_NW_ASSOC_FAIL           7
#define WPS_ERROR_NO_DHCP_RESP            8
#define WPS_ERROR_FAILED_DHCP_CONF        9
#define WPS_ERROR_IP_ADDR_CONFLICT        10
#define WPS_ERROR_FAIL_CONN_REGISTRAR     11
#define WPS_ERROR_MULTI_PBC_DETECTED      12
#define WPS_ERROR_ROGUE_SUSPECTED         13
#define WPS_ERROR_DEVICE_BUSY             14
#define WPS_ERROR_SETUP_LOCKED            15
#define WPS_ERROR_MSG_TIMEOUT             16
#define WPS_ERROR_REG_SESSION_TIMEOUT     17
#define WPS_ERROR_DEV_PWD_AUTH_FAIL       18

#define WPS_ERROR_MAX                      WPS_ERROR_DEV_PWD_AUTH_FAIL

// Connection types
#define WPS_CONNTYPE_ESS    0x01
#define WPS_CONNTYPE_IBSS   0x02

// Device password ID
#define WPS_DEVICEPWDID_DEFAULT          0x0000
#define WPS_DEVICEPWDID_USER_SPEC        0x0001
#define WPS_DEVICEPWDID_MACHINE_SPEC     0x0002
#define WPS_DEVICEPWDID_REKEY            0x0003
#define WPS_DEVICEPWDID_PUSH_BTN         0x0004
#define WPS_DEVICEPWDID_REG_SPEC         0x0005

/*
 // Device type
 #define WPS_DEVICETYPE_COMPUTER            "Computer"
 #define WPS_DEVICETYPE_AP                  "Access_Point"
 #define WPS_DEVICETYPE_ROUTER_AP           "Router_AP"
 #define WPS_DEVICETYPE_PRINTER             "Printer"
 #define WPS_DEVICETYPE_PRINTER_BRIDGE      "Printer_Brigde"
 #define WPS_DEVICETYPE_ELECT_PIC_FRAME     "Electronic_Picture_Frame"
 #define WPS_DEVICETYPE_DIG_AUDIO_RECV      "Digital_Audio_Receiver"
 #define WPS_DEVICETYPE_WIN_MCE             "Windows_Media_Center_Extender"
 #define WPS_DEVICETYPE_WIN_MOBILE          "Windows_Mobile"
 #define WPS_DEVICETYPE_PVR                 "Personal_Video_Recorder"
 #define WPS_DEVICETYPE_VIDEO_STB           "Video_STB"
 #define WPS_DEVICETYPE_PROJECTOR           "Projector"
 #define WPS_DEVICETYPE_IP_TV               "IP_TV"
 #define WPS_DEVICETYPE_DIG_STILL_CAM       "Digital_Still_Camera"
 #define WPS_DEVICETYPE_PHONE               "Phone"
 #define WPS_DEVICETYPE_VOID_PHONE          "VoIP_Phone"
 #define WPS_DEVICETYPE_GAME_CONSOLE        "Game_console"
 #define WPS_DEVICETYPE_OTHER               "Other"
 */

// Encryption type
#define WPS_ENCRTYPE_NONE    0x0001
#define WPS_ENCRTYPE_WEP     0x0002
#define WPS_ENCRTYPE_TKIP    0x0004
#define WPS_ENCRTYPE_AES     0x0008


// WPS Message Types
#define WPS_ID_BEACON            0x01
#define WPS_ID_PROBE_REQ         0x02
#define WPS_ID_PROBE_RESP        0x03
#define WPS_ID_MESSAGE_M1        0x04
#define WPS_ID_MESSAGE_M2        0x05
#define WPS_ID_MESSAGE_M2D       0x06
#define WPS_ID_MESSAGE_M3        0x07
#define WPS_ID_MESSAGE_M4        0x08
#define WPS_ID_MESSAGE_M5        0x09
#define WPS_ID_MESSAGE_M6        0x0A
#define WPS_ID_MESSAGE_M7        0x0B
#define WPS_ID_MESSAGE_M8        0x0C
#define WPS_ID_MESSAGE_ACK       0x0D
#define WPS_ID_MESSAGE_NACK      0x0E
#define WPS_ID_MESSAGE_DONE      0x0F

//Device Type categories for primary and secondary device types
#define WPS_DEVICE_TYPE_CAT_COMPUTER        1
#define WPS_DEVICE_TYPE_CAT_INPUT_DEVICE    2
#define WPS_DEVICE_TYPE_CAT_PRINTER         3
#define WPS_DEVICE_TYPE_CAT_CAMERA          4
#define WPS_DEVICE_TYPE_CAT_STORAGE         5
#define WPS_DEVICE_TYPE_CAT_NW_INFRA        6
#define WPS_DEVICE_TYPE_CAT_DISPLAYS        7
#define WPS_DEVICE_TYPE_CAT_MM_DEVICES      8
#define WPS_DEVICE_TYPE_CAT_GAME_DEVICES    9
#define WPS_DEVICE_TYPE_CAT_TELEPHONE       10

//Device Type sub categories for primary and secondary device types
#define WPS_DEVICE_TYPE_SUB_CAT_COMP_PC         1
#define WPS_DEVICE_TYPE_SUB_CAT_COMP_SERVER     2
#define WPS_DEVICE_TYPE_SUB_CAT_COMP_MEDIA_CTR  3
#define WPS_DEVICE_TYPE_SUB_CAT_PRTR_PRINTER    1
#define WPS_DEVICE_TYPE_SUB_CAT_PRTR_SCANNER    2
#define WPS_DEVICE_TYPE_SUB_CAT_CAM_DGTL_STILL  1
#define WPS_DEVICE_TYPE_SUB_CAT_STOR_NAS        1
#define WPS_DEVICE_TYPE_SUB_CAT_NW_AP           1
#define WPS_DEVICE_TYPE_SUB_CAT_NW_ROUTER       2
#define WPS_DEVICE_TYPE_SUB_CAT_NW_SWITCH       3
#define WPS_DEVICE_TYPE_SUB_CAT_DISP_TV         1
#define WPS_DEVICE_TYPE_SUB_CAT_DISP_PIC_FRAME  2
#define WPS_DEVICE_TYPE_SUB_CAT_DISP_PROJECTOR  3
#define WPS_DEVICE_TYPE_SUB_CAT_MM_DAR          1
#define WPS_DEVICE_TYPE_SUB_CAT_MM_PVR          2
#define WPS_DEVICE_TYPE_SUB_CAT_MM_MCX          3
#define WPS_DEVICE_TYPE_SUB_CAT_GAM_XBOX        1
#define WPS_DEVICE_TYPE_SUB_CAT_GAM_XBOX_360    2
#define WPS_DEVICE_TYPE_SUB_CAT_GAM_PS          3
#define WPS_DEVICE_TYPE_SUB_CAT_PHONE_WM        1

// Device request/response type
#define WPS_MSGTYPE_ENROLLEE_INFO_ONLY    0x00
#define WPS_MSGTYPE_ENROLLEE_OPEN_8021X   0x01
#define WPS_MSGTYPE_REGISTRAR             0x02
#define WPS_MSGTYPE_AP_WLAN_MGR           0x03

// RF Band
#define WPS_RFBAND_24GHZ    0x01
#define WPS_RFBAND_50GHZ    0x02

// Simple Config state
#define WPS_SCSTATE_UNCONFIGURED    0x01
#define WPS_SCSTATE_CONFIGURED      0x02

// State business
#define WPS_RETRY_INTERVAL    5    /* seconds */
#define WPS_PACKET_TIMEOUT    15    /* seconds */

#define WPS_TIMEOUT_SECS 1

enum WPSSupplicantState
{
    WPS_S_INIT,
    WPS_S_EAPOL_START_TX,
    WPS_S_EAPOL_START_RX,
    WPS_S_IDENT_REQ_TX,
    WPS_S_IDENT_REQ_RX,
    WPS_S_IDENT_RESP_TX,
    WPS_S_IDENT_RESP_RX,
    WPS_S_START_TX,
    WPS_S_START_RX,
    WPS_S_M1_TX,
    WPS_S_M1_RX,
    WPS_S_M2_TX,
    WPS_S_M2_RX,
    WPS_S_M3_TX,
    WPS_S_M3_RX,
    WPS_S_M4_TX,
    WPS_S_M4_RX,
    WPS_S_M5_TX,
    WPS_S_M5_RX,
    WPS_S_M6_TX,
    WPS_S_M6_RX,
    WPS_S_M7_TX,
    WPS_S_M7_RX,
    WPS_S_M8_TX,
    WPS_S_M8_RX,
    WPS_S_DONE_TX,
    WPS_S_DONE_RX,
    WPS_S_FAIL_TX,
    WPS_S_FAIL_RX,
    WPS_S_MSG_TIMEOUT,
    WPS_S_SESSION_TIMEOUT,
};
typedef enum WPSSupplicantState WPSSupplicantState;

// Apple specific error codes

#define WPSE_NOERR                 0        // no error
#define WPSE_ERR                -1        // general error code
#define    WPSE_PROTO_ERR            -2        // Problem with EAPOL handshake
#define    WPSE_IE_NOT_PRESENT        -3        // No WPS IE present in IE list for ssid
#define    WPSE_IE_MALFORMED        -4        // WPS IS missing required (for Apple) fields
#define    WPSE_SCAN_ERR            -5        // Scan failed
#define    WPSE_NO_PIN_AT_REG        -6        // No PIN configured at registrar
#define WPSE_NO_PIN_AT_CLIENT    -7        // No PIN configured at client
#define    WPSE_SSID_NOT_FOUND        -8        // Scan did not find SSID
#define    WPSE_UNSUPPORTED_PW_ID    -9        // Registrar reports that it is using an unsupported PW ID
#define    WPSE_ASSOC_FAILED        -10        // Association attempt failed
#define WPSE_API_REQ            -11        // An apple80211 ioctl request failed
#define WPSE_NOMEM                -12        // memory error
#define WPSE_WPA_RSN_NOT_SUP    -13        // WPA/RSN not supported
#define WPSE_TIMEOUT            -14        // EAPOL timed out
#define WPSE_NACKED                -15        // NACKED by registrar
#define WPSE_FAIL                -16        // unexpected EAP-FAIL received

#endif /* WPS_EAP_H */

