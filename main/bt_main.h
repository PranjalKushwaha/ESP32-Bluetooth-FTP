#pragma once

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_bt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/*  HCI Command opcode group field(OGF) */
#define HCI_GRP_HOST_CONT_BASEBAND_CMDS (0x03 << 10) /* 0x0C00 */

#define HCI_RESET (0x0003 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)

#define HCI_CHANGE_LOCAL_NAME (0x0013 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCIC_PARAM_SIZE_SET_SCAN_MODE 2
#define HCI_SCAN_ENABLE (0x03 << 10)
#define HCI_SET_SCAN_MODE (0x001a | HCI_SCAN_ENABLE)

#define HCI_ACCEPT_OGF (0X01 << 10)
#define HCI_ACCEPT (0X0009 | HCI_ACCEPT_OGF)

#define BD_ADDR_LEN (6) /* Device address length */

#define MAX_OBEX_PACK 500   // Maximum obex payload
#define SEND_BUFFER_SIZE 10 // Max Number of packets queued to be sent
#define MAX_CMD_LEN 300     // Max HCI command length
#define DEBUG false         // Set to true to log packet contents to stdout

// Functions to help write to the command buffer
#define UINT16_TO_STREAM(p, u16)        \
    {                                   \
        *(p)++ = (uint8_t)(u16);        \
        *(p)++ = (uint8_t)((u16) >> 8); \
    }
#define UINT8_TO_STREAM(p, u8)  \
    {                           \
        *(p)++ = (uint8_t)(u8); \
    }
#define BDADDR_TO_STREAM(p, a)                          \
    {                                                   \
        int ijk;                                        \
        for (ijk = 0; ijk < BD_ADDR_LEN; ijk++)         \
            *(p)++ = (uint8_t)a[BD_ADDR_LEN - 1 - ijk]; \
    }
#define ARRAY_TO_STREAM(p, a, len)      \
    {                                   \
        int ijk;                        \
        for (ijk = 0; ijk < len; ijk++) \
            *(p)++ = (uint8_t)a[ijk];   \
    }
#define HCI_H4_CMD_PREAMBLE_SIZE (4)
/**
 * @brief HCI packet type list
 */
typedef enum
{
    H4_TYPE_COMMAND = 1,
    H4_TYPE_ACL = 2,
    H4_TYPE_SCO = 3,
    H4_TYPE_EVENT = 4
} hci_packet_t;

/**
 * @brief HCI events list (src:esp-idf/components/bt/host/bluedroid/stack/include/stack/hcidefs.h)
 */
typedef enum
{
    HCI_EVT_INQUIRY_COMPLETE = 0X01,
    HCI_EVT_INQUIRY_RES = 0X02,
    HCI_EVT_CONN_COMPLETE = 0X03,
    HCI_EVT_CONN_REQ = 0X04,
    HCI_EVT_DISCONN_COMPLETE = 0X05,
    HCI_EVT_AUTH_COMPLETE = 0X06,
    HCI_EVT_NAME_REQ_COMPLETE = 0X07,
    HCI_EVT_ENCRYPT_CHANGE_COMPLETE = 0X08,
    HCI_EVT_LINK_KEY_CHANGE_COMPLETE = 0X09,
    HCI_EVT_MASTER_LINK_KEY_CHG_COMPLETE = 0X0A,
    HCI_EVT_READ_REM_FEAT_COMPLETE = 0X0B,
    HCI_EVT_READ_REM_VER_COMPLETE = 0X0C,
    HCI_EVT_QOS_SETUP_COMPLETE = 0X0D,
    HCI_EVT_CMD_COMPLETE = 0X0E,
    HCI_EVT_CMD_STAT = 0X0F,
    HCI_EVT_HARDWARE_ERR = 0X10,
    HCI_EVT_DATA_FLUSHED = 0X11,
    HCI_EVT_ROLE_CHANGE = 0X12,
    HCI_EVT_NUM_PACK_SENT = 0X13,
    HCI_EVT_MODE_CHANGE = 0X14,
    HCI_EVT_RET_LINK_KEYS = 0X15,
    HCI_EVT_PIN_CODE_REQ = 0X16,
    HCI_EVT_LINK_KEY_REQ = 0X17,
    HCI_EVT_LINK_KEY_NOTIF = 0X18,
    HCI_EVT_LO_CMD = 0X19,
    HCI_EVT_DATA_BUFF_OVERFLOW = 0X1A,
    HCI_EVT_MAX_SLOTS_CHANGE = 0X1B,
    HCI_EVT_READ_CLK_OFFSET_COMPLETE = 0X1C,
    HCI_EVT_CONN_PACK_TYPE_CHG = 0X1D,
    HCI_EVT_QOS_VIOLATION = 0X1E,
    HCI_EVT_PAGE_SCAN_MODE_CHG = 0X1F,
    HCI_EVT_PAGE_SCAN_REP_MODE_CHG = 0X20,
    HCI_FLOW_SPECIFICATION_COMP_EVT = 0x21,
    HCI_INQUIRY_RSSI_RESULT_EVT = 0x22,
    HCI_READ_RMT_EXT_FEATURES_COMP_EVT = 0x23,
    HCI_ESCO_CONNECTION_COMP_EVT = 0x2C,
    HCI_ESCO_CONNECTION_CHANGED_EVT = 0x2D,
    HCI_SNIFF_SUB_RATE_EVT = 0x2E,
    HCI_EXTENDED_INQUIRY_RESULT_EVT = 0x2F,
    HCI_ENCRYPTION_KEY_REFRESH_COMP_EVT = 0x30,
    HCI_IO_CAPABILITY_REQUEST_EVT = 0x31,
    HCI_IO_CAPABILITY_RESPONSE_EVT = 0x32,
    HCI_USER_CONFIRMATION_REQUEST_EVT = 0x33,
    HCI_USER_PASSKEY_REQUEST_EVT = 0x34,
    HCI_REMOTE_OOB_DATA_REQUEST_EVT = 0x35,
    HCI_SIMPLE_PAIRING_COMPLETE_EVT = 0x36,
    HCI_LINK_SUPER_TOUT_CHANGED_EVT = 0x38,
    HCI_ENHANCED_FLUSH_COMPLETE_EVT = 0x39,
    HCI_USER_PASSKEY_NOTIFY_EVT = 0x3B,
    HCI_KEYPRESS_NOTIFY_EVT = 0x3C,
    HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT = 0x3D
} hci_event_t;

/**
 * @brief L2CAP packet type list
 */
typedef enum
{
    L2CAP_CMD_REJECT = 0X01,
    L2CAP_CMD_CONN_REQ = 0X02,
    L2CAP_CMD_CONN_RES = 0X03,
    L2CAP_CMD_CONF_REQ = 0X04,
    L2CAP_CMD_CONF_RES = 0X05,
    L2CAP_CMD_DISCONN_REQ = 0X06,
    L2CAP_CMD_DISCONN_RES = 0X07,
    L2CAP_CMD_ECHO_REQ = 0X08,
    L2CAP_CMD_ECHO_RES = 0X09,
    L2CAP_CMD_INFO_REQ = 0X0A,
    L2CAP_CMD_INFO_RES = 0X0B
} l2cap_cmd_t;

/**
 * @brief SDP packet type list
 */
typedef enum
{
    SDP_ATT_REQ = 0X06,
    SDP_ATT_RES = 0X07
} sdp_type_t;

// Pairing pin
extern const char pin[];

// File handler
extern void obex_ftp(uint8_t *packet, uint16_t len);

// Main func
void init_bt(void);

#ifdef __cplusplus
}
#endif // __cplusplus
