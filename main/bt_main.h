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

/*
 * Lookup table for crc16 function
 * Source: https://kernel.googlesource.com/pub/scm/linux/kernel/git/bluetooth/bluetooth/+/for-upstream/lib/crc16.c
 */
uint16_t const crc16_table[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040};

//Pairing pin
char pin[] = "1234";

#ifdef __cplusplus
}
#endif // __cplusplus
