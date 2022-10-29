
#include <stdint.h>
#include <stdio.h>
#include "bt_main.h"
#include "nvs_flash.h"
#include "freertos/queue.h"

static const char *tag = "BT-ADV"; // Device name(as seen by connected devices)
uint8_t obex_cid = 0;              // Obex connection id, modified on ftp recieving connection request
uint8_t connected = 0;
uint16_t src_cid = 0;     // L2CAP sourde id, modified on L2CAP connection request
uint16_t dest_cid = 0x41; // L2CAP Destination id, incremented for each new connection

uint16_t mtu = 0; // Stores the most recently agreed MTU value
uint16_t obex_conn_id = 1;
uint8_t *file_name;
uint32_t file_ptr = 0; // Mark current recieve index
uint32_t file_len = -1;
uint64_t file_sum = 0; // Sums all bytes of the recieved file body(for basic error detection)

uint8_t queue_storage[SEND_BUFFER_SIZE * MAX_CMD_LEN]; // Storage for Xqueue
static StaticQueue_t xStaticQueue;
static QueueHandle_t queue_handle; // Send queue handle

__attribute__((weak)) const char pin[] = "1234";

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

/*
 * Initialises the send queue.
 * Restarts the cpu upon failure.
 */
void init_queue()
{
    queue_handle = xQueueCreateStatic(SEND_BUFFER_SIZE, MAX_CMD_LEN, queue_storage, &xStaticQueue);
    if (queue_handle == NULL)
    {
        ESP_LOGE(tag, "Queue initialisation failed, Restarting......");
        esp_restart();
    }
    if (DEBUG)
    {
        ESP_LOGI(tag, "Send queue initialised.");
    }
}

/*
 * Appends new packet to the end of the queue.
 * Since freertos queue append is atomic, it does not conflict with send()
 */
void queue_packet(uint8_t *packet)
{
    while (xQueueSend(queue_handle, packet, 0) != pdTRUE)
        ;
    if (DEBUG)
    {
        // Each packet has the first two bytes store its length
        uint16_t pack_len = packet[0] * 256 + packet[1];
        ESP_LOGI(tag, "Queued packet :--");
        for (int i = 2; i < pack_len; i++)
        {
            printf("%02x ", packet[i]);
        }
        printf("\n");
        fflush(stdout);
    }
}

/*
 * Will be run as a separate task.
 * Every few ticks if the vhci controller is ready, pop a packet from the queue and send it.
 * Packet is queued from byte 3 removing the length data(byte 1 and 2).
 */
void send(void *pvParameters)
{
    uint8_t packet[MAX_CMD_LEN];
    while (1)
    {
        // Yeild priority frequently to prevent WDT crash
        vTaskDelay(10 / portTICK_PERIOD_MS);
        // Returns true if vhci controller is accepting new packets
        if (esp_vhci_host_check_send_available())
        {
            if (xQueueReceive(queue_handle, packet, 0) == pdTRUE)
            {
                esp_vhci_host_send_packet(&packet[2], packet[0] * 256 + packet[1]);
                if (DEBUG)
                {
                    uint16_t pack_len = packet[0] * 256 + packet[1];
                    ESP_LOGI(tag, "Sent packet :--");
                    for (int i = 2; i < pack_len; i++)
                    {
                        printf("%02x ", packet[i]);
                    }
                    printf("\n");
                    fflush(stdout);
                }
            }
        }
    }
}

/*
 * Generates the Frame Check Sequence(FCS) for the obex packets
 * Source: https://kernel.googlesource.com/pub/scm/linux/kernel/git/bluetooth/bluetooth/+/for-upstream/lib/crc16.c
 */
static inline uint16_t crc16_byte(uint16_t crc, uint8_t data)
{
    return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

/*
 * Generates the Frame Check Sequence(FCS) for the obex packets
 * Takes array of uint8_t and returns a 2 byte crc value.
 * Source: https://kernel.googlesource.com/pub/scm/linux/kernel/git/bluetooth/bluetooth/+/for-upstream/lib/crc16.c
 */
uint16_t crc16(uint16_t crc, uint8_t *buffer, uint32_t len)
{
    while (len--)
    {
        crc = crc16_byte(crc, *buffer++);
    }
    return crc;
}

/*
 * Handles the L2CAP configuration process
 * buf : will be filled with the configuration response
 * packet : contains request by peer device
 * len : length of packet
 * For detailed packet formats refer the Bluetooth 4.2 spec:
 * https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=441541
 */
void conf_req(uint8_t *buf, uint8_t *packet, uint16_t len)
{
    uint16_t pack_len = 0;
    /*
     * Two L2CAP config options have been implemented
     * 0x01 byte at position 17 means an MTU request
     * 0x04 means an extended feature mask(EFM) request
     */

    // Only MTU request
    if (packet[17] == 0x01 && len < 22)
    {
        pack_len = 23;
        UINT8_TO_STREAM(buf, pack_len / 256);
        UINT8_TO_STREAM(buf, pack_len % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_ACL);                   // Packet type(ACL)
        UINT16_TO_STREAM(buf, 256U * packet[2] + packet[1]); // ACL flags
        UINT16_TO_STREAM(buf, 18);                           // Length data
        UINT16_TO_STREAM(buf, 14);                           // Length data
        UINT16_TO_STREAM(buf, 256U * packet[8] + packet[7]); // signalling channel
        UINT8_TO_STREAM(buf, L2CAP_CMD_CONF_RES);            // L2CAP Packet type (Config response)
        UINT8_TO_STREAM(buf, packet[10]);                    // command identifier
        UINT16_TO_STREAM(buf, 10);                           // Length
        UINT16_TO_STREAM(buf, src_cid);                      // Source channel id
        UINT16_TO_STREAM(buf, 0);                            // Success
        UINT16_TO_STREAM(buf, 0);
        UINT8_TO_STREAM(buf, 0x01);                            // MTU info
        UINT8_TO_STREAM(buf, 0x02);                            // Info length
        UINT16_TO_STREAM(buf, packet[20] * 256U + packet[19]); // Agree to the recieved MTU value

        mtu = packet[20] * 256U + packet[19];
    }

    // MTU and EFM request
    else if (packet[17] == 0x01 && packet[21] == 0x04)
    {
        pack_len = 34;
        UINT8_TO_STREAM(buf, pack_len / 256);
        UINT8_TO_STREAM(buf, pack_len % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_ACL);
        UINT16_TO_STREAM(buf, 256U * packet[2] + packet[1]); // acl flags
        UINT16_TO_STREAM(buf, 29);
        UINT16_TO_STREAM(buf, 25);
        UINT16_TO_STREAM(buf, 256U * packet[8] + packet[7]); // sig channel
        UINT8_TO_STREAM(buf, L2CAP_CMD_CONF_RES);
        UINT8_TO_STREAM(buf, packet[10]); // identifier
        UINT16_TO_STREAM(buf, 21);
        UINT16_TO_STREAM(buf, src_cid);
        UINT16_TO_STREAM(buf, 0);
        UINT16_TO_STREAM(buf, 0);
        UINT8_TO_STREAM(buf, 0x01); // MTU info
        UINT8_TO_STREAM(buf, 0x02);
        mtu = packet[20] * 256U + packet[19];
        UINT16_TO_STREAM(buf, mtu);
        UINT8_TO_STREAM(buf, 0x04); // EFM info
        UINT8_TO_STREAM(buf, 0x09);
        UINT8_TO_STREAM(buf, 0x03);
        UINT8_TO_STREAM(buf, 0x0a);
        UINT8_TO_STREAM(buf, 0x14);
        UINT16_TO_STREAM(buf, 2000);
        UINT16_TO_STREAM(buf, 12000);
        UINT16_TO_STREAM(buf, 1010)
    }
    // Only EFM request (flow control mode)
    else if (packet[17] == 0x04 && packet[19] == 0x00)
    {
        pack_len = 21;
        UINT8_TO_STREAM(buf, pack_len / 256);
        UINT8_TO_STREAM(buf, pack_len % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_ACL);
        UINT16_TO_STREAM(buf, 256U * packet[2] + packet[1]); // acl flags
        UINT16_TO_STREAM(buf, 16);
        UINT16_TO_STREAM(buf, 12);
        UINT16_TO_STREAM(buf, 256U * packet[8] + packet[7]); // sig channel
        UINT8_TO_STREAM(buf, 0x04);
        UINT8_TO_STREAM(buf, packet[10]); // identifier
        UINT16_TO_STREAM(buf, 8);
        UINT16_TO_STREAM(buf, src_cid);
        UINT16_TO_STREAM(buf, 0);
        UINT8_TO_STREAM(buf, 0x01);
        UINT8_TO_STREAM(buf, 0x02);
        UINT16_TO_STREAM(buf, 1024);
        mtu = 1024;
    }
    // Only EFM request (retransmission and flow control mode)
    else if (packet[17] == 0x04 && packet[19] == 0x03)
    {
        pack_len = 32;
        UINT8_TO_STREAM(buf, pack_len / 256);
        UINT8_TO_STREAM(buf, pack_len % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_ACL);
        UINT16_TO_STREAM(buf, 256U * packet[2] + packet[1]); // acl flags
        UINT16_TO_STREAM(buf, 27);
        UINT16_TO_STREAM(buf, 23);
        UINT16_TO_STREAM(buf, 256U * packet[8] + packet[7]); // sig channel
        UINT8_TO_STREAM(buf, 0x04);
        UINT8_TO_STREAM(buf, packet[10]); // identifier
        UINT16_TO_STREAM(buf, 19);
        UINT16_TO_STREAM(buf, src_cid);
        UINT16_TO_STREAM(buf, 0);
        UINT8_TO_STREAM(buf, 0x01);
        UINT8_TO_STREAM(buf, 0x02);
        UINT16_TO_STREAM(buf, 1024);
        mtu = 1024;
        uint8_t ertm[] =
            {0x04, 0x09, 0x03, 0x0a, 0x14, 0xd0, 0x07, 0xe0, 0x2e, 0xf2, 0x03};

        ARRAY_TO_STREAM(buf, ertm, sizeof(ertm));
    }
}

/*
 * Handles the OBEX L2CAP packets
 * Prints the name of the file and sums the recieved file contents
 * Can be edited to store the file as well
 * For OBEX packet format refer the IRDA spec:
 * https://btprodspecificationrefs.blob.core.windows.net/ext-ref/IrDA/OBEX15.pdf
 */
void __attribute__((weak)) obex_ftp(uint8_t *packet, uint16_t len)
{
    uint16_t pack_len = 0;
    uint8_t cmd_buf[MAX_CMD_LEN]; // Stores the packet to be sent
    uint8_t *buf = cmd_buf;       // Copy of base address(helps in creating the packet)
    memset(cmd_buf, 0, sizeof(cmd_buf));
    uint16_t acl_flags = 256U * packet[2] + packet[1];
    uint8_t command = packet[11] & 0b01111111; // Get the OBEX command opcode

    uint8_t send = 0;
    uint16_t fcs = 0;
    uint8_t obex_reqseq = packet[10] & 0b00111111; // Recieved REQ seq
    uint8_t obex_txseq = packet[9] & 0b01111110;   // Recieved TX seq

    uint8_t frame_type = packet[9] & 0b00000001; // Obex frame type
    if (((obex_txseq >> 1) + 1) % 8 == 0)        // Send a recieved acknowledgement after every 8 packets
    {
        pack_len = 13;
        UINT8_TO_STREAM(buf, pack_len / 256);
        UINT8_TO_STREAM(buf, pack_len % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_ACL);
        UINT16_TO_STREAM(buf, acl_flags);
        UINT16_TO_STREAM(buf, 8);
        UINT16_TO_STREAM(buf, 4);
        UINT16_TO_STREAM(buf, src_cid);
        UINT8_TO_STREAM(buf, 0x01)
        uint8_t tx = ((obex_txseq >> 1) + 1);
        UINT8_TO_STREAM(buf, tx);

        fcs = crc16(0, &cmd_buf[7], 6);
        UINT16_TO_STREAM(buf, fcs);

        queue_packet(cmd_buf);

        buf = cmd_buf;
    }
    if (frame_type == 0) // I Frame
    {
        switch (command)
        {
        case 0x00: // Obex connect
            send = 1;
            pack_len = 25;
            UINT8_TO_STREAM(buf, pack_len / 256);
            UINT8_TO_STREAM(buf, pack_len % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_ACL);
            UINT16_TO_STREAM(buf, acl_flags);
            UINT16_TO_STREAM(buf, 20);
            UINT16_TO_STREAM(buf, 16);
            UINT16_TO_STREAM(buf, src_cid);
            UINT8_TO_STREAM(buf, 0x00);
            UINT8_TO_STREAM(buf, 0x01);
            UINT8_TO_STREAM(buf, 0xa0);
            UINT8_TO_STREAM(buf, 0);
            UINT8_TO_STREAM(buf, 0x0c);
            UINT8_TO_STREAM(buf, 0X10);
            UINT8_TO_STREAM(buf, 0x00);
            UINT8_TO_STREAM(buf, MAX_OBEX_PACK / 256); // Maximum acceptable packet length
            UINT8_TO_STREAM(buf, MAX_OBEX_PACK % 256);
            UINT8_TO_STREAM(buf, 0xcb);
            UINT16_TO_STREAM(buf, 0x00);
            UINT8_TO_STREAM(buf, obex_conn_id / 256);
            UINT8_TO_STREAM(buf, obex_conn_id % 256);

            fcs = crc16(0, &cmd_buf[7], 18);
            UINT16_TO_STREAM(buf, fcs); // FCS

            break;
        case 0x02: // Obex PUT(Send file)
            // Parse packet using a loop
            for (int i = 14; i < len - 2;)
            {
                // Segment contains connection id
                if (packet[i] == 0xcb)
                {
                    i += 5;
                }
                // Segment contains the file name
                else if (packet[i] == 0x01)
                {
                    uint16_t head_len = packet[i + 1] * 256 + packet[i + 2];
                    // Uncommment these two lines to store the file name
                    // file_name = (uint8_t *)malloc(head_len - 3);
                    // memcpy(file_name, &packet[i + 3], head_len - 3);
                    printf("Recieving File : ");
                    for (int j = i + 4; j < head_len + i; j += 2)
                        printf("%c", packet[j]);
                    i += head_len;
                    printf("\n");
                    fflush(stdout);
                }
                // Segment contains file size(number of bytes)
                else if (packet[i] == 0xc3)
                {
                    for (int j = 1; j <= 4; j++)
                        file_len = (file_len << 8) + packet[i + j];
                    i += 5;
                }
                // Contains file contents
                else if (packet[i] == 0x48)
                {
                    /*
                     * To store the recieved file malloc memory of size "file_len".
                     *
                     */
                    uint16_t head_len = packet[i + 1] * 256 + packet[i + 2];
                    // printf("File contents : \n");
                    // Just suming the file contents
                    for (int j = i + 3; j < head_len + i; j++)
                    {
                        file_sum += packet[j];
                        // printf("%c", packet[j]);
                    }
                    i += head_len;
                }
                // Contains file type info
                else if (packet[i] == 0x42)
                {
                    uint16_t head_len = packet[i + 1] * 256 + packet[i + 2];
                    i += head_len;
                }
                // Enable Single Response Mode request
                else if (packet[i] == 0x97)
                {
                    send = 1;
                    pack_len = 18;
                    UINT8_TO_STREAM(buf, pack_len / 256);
                    UINT8_TO_STREAM(buf, pack_len % 256);
                    UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                    UINT16_TO_STREAM(buf, acl_flags);
                    UINT16_TO_STREAM(buf, 13);
                    UINT16_TO_STREAM(buf, 9);
                    UINT16_TO_STREAM(buf, src_cid);
                    UINT8_TO_STREAM(buf, obex_reqseq << 1);
                    UINT8_TO_STREAM(buf, (obex_txseq >> 1) + 1);
                    UINT8_TO_STREAM(buf, 0x90);
                    UINT8_TO_STREAM(buf, 0x00);
                    UINT8_TO_STREAM(buf, 0x05);
                    UINT8_TO_STREAM(buf, 0x97);
                    UINT8_TO_STREAM(buf, 0x01);
                    fcs = crc16(0, &cmd_buf[7], 11);
                    UINT16_TO_STREAM(buf, fcs); // FCS
                    // printf("SRM\n");
                    i += 2;
                }
                // End of body packet
                else if (packet[i] == 0x49)
                {
                    send = 1;
                    pack_len = 16;
                    UINT8_TO_STREAM(buf, pack_len / 256);
                    UINT8_TO_STREAM(buf, pack_len % 256);
                    UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                    UINT16_TO_STREAM(buf, acl_flags);
                    UINT16_TO_STREAM(buf, 11);
                    UINT16_TO_STREAM(buf, 7);
                    UINT16_TO_STREAM(buf, src_cid);
                    UINT8_TO_STREAM(buf, obex_reqseq << 1);
                    UINT8_TO_STREAM(buf, (obex_txseq >> 1) + 1);
                    UINT8_TO_STREAM(buf, 0xa0);
                    UINT8_TO_STREAM(buf, 0x00);
                    UINT8_TO_STREAM(buf, 0x03);
                    fcs = crc16(0, &cmd_buf[7], 9);
                    UINT16_TO_STREAM(buf, fcs); // FCS
                    i += 3;
                    printf("File recieved successfully\n");
                    printf("File sum : %lld\n", file_sum);
                    fflush(stdout);
                    // printf("End of file \n");
                }
            }

            break;
        }
    }
    if (send)
    {
        queue_packet(cmd_buf);
    }
}

/*
 * Handles the HCI requests
 * Called from the host_rcv_pkt() callback function
 */
void hci_event_handler(uint8_t *packet, uint16_t len)
{
    uint8_t event = packet[1]; // packet[0] contains 0x04(HCI_EVENT), packet[1] contains the event type.
    uint8_t cmd_buf[MAX_CMD_LEN];
    uint8_t *buf = cmd_buf;
    uint16_t pack_size = 0;
    memset(cmd_buf, 0, sizeof(cmd_buf));
    switch (event)
    {
    case HCI_EVT_CONN_REQ:
        if (!connected)
        {
            pack_size = HCI_H4_CMD_PREAMBLE_SIZE + 7;
            UINT8_TO_STREAM(buf, pack_size / 256);
            UINT8_TO_STREAM(buf, pack_size % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);      // HCI command packet
            UINT16_TO_STREAM(buf, 0x0009 | 0x01 << 10); // Opcode for operation (OCF | OGF << 10) (src : https://lisha.ufsc.br/teaching/shi/ine5346-2003-1/work/bluetooth/hci_commands.html)
            UINT8_TO_STREAM(buf, 7);                    // length of params
            for (int i = 3; i < 9; i++)                 // Bt MAC address of device to be connected to.
            {
                UINT8_TO_STREAM(buf, packet[i]);
            }
            UINT8_TO_STREAM(buf, 1); // Become slave node for the connection (set 0 if master is required)
            queue_packet(cmd_buf);
        }
        else
        {
            pack_size = HCI_H4_CMD_PREAMBLE_SIZE + 7;
            UINT8_TO_STREAM(buf, pack_size / 256);
            UINT8_TO_STREAM(buf, pack_size % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);
            UINT16_TO_STREAM(buf, 0x000A | 0x01 << 10);
            UINT8_TO_STREAM(buf, 7);
            for (int i = 3; i < 9; i++)
            {
                UINT8_TO_STREAM(buf, packet[i]);
            }
            UINT8_TO_STREAM(buf, 1);
            queue_packet(cmd_buf);
        }
        break;
    case HCI_EVT_PIN_CODE_REQ:
        pack_size = HCI_H4_CMD_PREAMBLE_SIZE + 23;
        UINT8_TO_STREAM(buf, pack_size / 256);
        UINT8_TO_STREAM(buf, pack_size % 256);
        UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);
        UINT16_TO_STREAM(buf, 0x000D | 0x01 << 10);
        UINT8_TO_STREAM(buf, 23);
        for (int i = 3; i < 9; i++)
        {
            UINT8_TO_STREAM(buf, packet[i]);
        }
        UINT8_TO_STREAM(buf, strlen(pin));
        for (int i = 0; i < strlen(pin); i++)
        {
            UINT8_TO_STREAM(buf, pin[i]);
        }
        queue_packet(cmd_buf);
        break;
    }
}

/*
 * L2CAP request handler
 * Manages multiplexing between Service Discovery Protocol(SDP), OBEX and normal L2CAP packets
 */
void l2cap_cmd_handler(uint8_t *packet, uint16_t len)
{
    uint8_t send = 0; // A packet is queued only if send is set to 1(Some requests do not generate a response)
    uint16_t pack_len = 0;
    uint8_t cmd_buf[MAX_CMD_LEN];
    uint8_t *buf = cmd_buf;
    memset(cmd_buf, 0, sizeof(cmd_buf));
    uint16_t acl_flags = 256U * packet[2] + packet[1];   // ACL transmission flags
    uint16_t sig_channel = 256U * packet[8] + packet[7]; // L2CAP signalling channel
    uint8_t command = packet[9];
    if (sig_channel == 0x01) // L2CAP packet (sig channel 0x0001 is reserved for L2CAP)
    {
        uint8_t identifier = packet[10];
        switch (command)
        {
            // Information request
        case L2CAP_CMD_INFO_REQ:
            // Supported features request
            if (packet[13] == 0x02)
            {
                pack_len = 21;
                uint16_t features = 0x02b8;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 16);
                UINT16_TO_STREAM(buf, 12);
                UINT16_TO_STREAM(buf, sig_channel);
                UINT8_TO_STREAM(buf, 0x0b);
                UINT8_TO_STREAM(buf, identifier);
                UINT16_TO_STREAM(buf, 8);
                UINT16_TO_STREAM(buf, 0x02);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, features);
                UINT16_TO_STREAM(buf, 0);
                send = 1;
            }
            /*
             * Fixed channels supported request (only 1 fixed channel (0x0001 L2CAP) is supported)
             * Other signalling channels(OBEX, SDP) have to be negotiated
             */
            else if (packet[13] == 0x03)
            {
                pack_len = 25;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 20);
                UINT16_TO_STREAM(buf, 16);
                UINT16_TO_STREAM(buf, sig_channel);
                UINT8_TO_STREAM(buf, 0x0b);
                UINT8_TO_STREAM(buf, identifier);
                UINT16_TO_STREAM(buf, 12);
                UINT16_TO_STREAM(buf, 0x0003);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0x86);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0);

                send = 1;
            }
            break;
        // Recieved connection request for use of a channel
        case L2CAP_CMD_CONN_REQ:
        {
            // Accept connection
            pack_len = 21;
            UINT8_TO_STREAM(buf, pack_len / 256);
            UINT8_TO_STREAM(buf, pack_len % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_ACL);
            UINT16_TO_STREAM(buf, acl_flags);
            UINT16_TO_STREAM(buf, 16);
            UINT16_TO_STREAM(buf, 12);
            UINT16_TO_STREAM(buf, sig_channel);
            UINT8_TO_STREAM(buf, 0x03);
            UINT8_TO_STREAM(buf, identifier);
            UINT16_TO_STREAM(buf, 8);
            UINT16_TO_STREAM(buf, dest_cid);
            src_cid = 256U * packet[16] + packet[15];
            UINT16_TO_STREAM(buf, src_cid);
            UINT16_TO_STREAM(buf, 0);
            UINT16_TO_STREAM(buf, 0);

            queue_packet(cmd_buf);

            memset(cmd_buf, 0, sizeof(cmd_buf));
            buf = cmd_buf;

            /*
             * If UUID = 0x1009(OBEXObjectPush) store the channel id and send ertm config
             */
            if (packet[13] == 0x09 && packet[14] == 0x10)
            {
                obex_cid = dest_cid;
                memset(cmd_buf, 0, sizeof(cmd_buf));
                buf = cmd_buf;
                pack_len = 28;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 23);
                UINT16_TO_STREAM(buf, 19);
                UINT16_TO_STREAM(buf, sig_channel);
                UINT8_TO_STREAM(buf, 0x04);
                UINT8_TO_STREAM(buf, identifier + 1);
                UINT16_TO_STREAM(buf, 15);
                UINT16_TO_STREAM(buf, src_cid);
                UINT16_TO_STREAM(buf, 0);
                UINT8_TO_STREAM(buf, 0x04);
                UINT8_TO_STREAM(buf, 0x09);
                UINT8_TO_STREAM(buf, 0x03);
                UINT8_TO_STREAM(buf, 63);
                UINT8_TO_STREAM(buf, 3);
                UINT16_TO_STREAM(buf, 2000);
                UINT16_TO_STREAM(buf, 12000);
                UINT16_TO_STREAM(buf, 1012);

                send = 1;
            }
            else
            {
                pack_len = 28;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 23);
                UINT16_TO_STREAM(buf, 19);
                UINT16_TO_STREAM(buf, sig_channel);
                UINT8_TO_STREAM(buf, 0x04);
                UINT8_TO_STREAM(buf, identifier + 1);
                UINT16_TO_STREAM(buf, 15);
                UINT16_TO_STREAM(buf, src_cid);
                UINT16_TO_STREAM(buf, 0);
                UINT8_TO_STREAM(buf, 4);
                UINT8_TO_STREAM(buf, 9);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0);
                UINT16_TO_STREAM(buf, 0);
                UINT8_TO_STREAM(buf, 0);

                send = 1;
            }
            dest_cid++;
        }
        break;
        // L2CAP Configuration request packet
        case L2CAP_CMD_CONF_REQ:

            conf_req(buf, packet, len);
            send = 1;
            break;

        // L2CAP Configuration response
        case L2CAP_CMD_CONF_RES:
            pack_len = 19;
            UINT8_TO_STREAM(buf, pack_len / 256);
            UINT8_TO_STREAM(buf, pack_len % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_ACL);
            UINT16_TO_STREAM(buf, acl_flags);
            UINT16_TO_STREAM(buf, 14);
            UINT16_TO_STREAM(buf, 10);
            UINT16_TO_STREAM(buf, sig_channel);
            UINT8_TO_STREAM(buf, 0x05);
            UINT8_TO_STREAM(buf, identifier);
            UINT16_TO_STREAM(buf, 6);
            UINT16_TO_STREAM(buf, src_cid);
            UINT16_TO_STREAM(buf, 0);
            UINT16_TO_STREAM(buf, 0);

            send = 1;
            break;

        // Disconnection request
        case L2CAP_CMD_DISCONN_REQ:
            pack_len = 17;
            UINT8_TO_STREAM(buf, pack_len / 256);
            UINT8_TO_STREAM(buf, pack_len % 256);
            UINT8_TO_STREAM(buf, H4_TYPE_ACL);
            UINT16_TO_STREAM(buf, acl_flags);
            UINT16_TO_STREAM(buf, 12);
            UINT16_TO_STREAM(buf, 8);
            UINT16_TO_STREAM(buf, sig_channel);
            UINT8_TO_STREAM(buf, 0x07);
            UINT8_TO_STREAM(buf, identifier);
            UINT16_TO_STREAM(buf, 4);

            UINT16_TO_STREAM(buf, 256U * packet[14] + packet[13]);
            UINT16_TO_STREAM(buf, 256U * packet[16] + packet[15]);

            send = 1;
            break;
        }
    }

    // Obex packet
    else if (sig_channel == obex_cid)
    {

        obex_ftp(packet, len);
        return;
    }
    else // SDP packet
    {
        switch (command)
        {
        case SDP_ATT_REQ:
            /*
             * Attribute request
             * Sending OBEX as the only supported service
             */
            if ((packet[17] == 0x01 && packet[18] == 0x00) || (packet[17] == 0x11 && packet[18] == 0x05))
            {
                pack_len = 121;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 116); // len  99

                UINT16_TO_STREAM(buf, 112); // len-4  95
                UINT16_TO_STREAM(buf, src_cid);
                UINT8_TO_STREAM(buf, 0x07);
                uint16_t txn_id = 256U * packet[11] + packet[10];
                UINT16_TO_STREAM(buf, txn_id);
                UINT16_TO_STREAM(buf, 0x6b00); // 275  // Param len
                UINT16_TO_STREAM(buf, 0x6800); // 272

                uint8_t obex_push[] = {
                    0x35, 0x66, 0x35, 0x64, 0x09, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x0e, 0x09, 0x00, 0x01, 0x35,
                    0x03, 0x19, 0x11, 0x05, 0x09, 0x00, 0x04, 0x35, 0x11, 0x35, 0x03, 0x19, 0x01, 0x00, 0x35, 0x05,
                    0x19, 0x00, 0x03, 0x08, 0x09, 0x35, 0x03, 0x19, 0x00, 0x08, 0x09, 0x00, 0x05, 0x35, 0x03, 0x19,
                    0x10, 0x02, 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x05, 0x09, 0x01, 0x02, 0x09,
                    0x01, 0x00, 0x25, 0x0b, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x20, 0x50, 0x75, 0x73, 0x68, 0x09,
                    0x02, 0x00, 0x09, 0x10, 0x09, 0x09, 0x03, 0x03, 0x35, 0x0e, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03,
                    0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0xff};

                ARRAY_TO_STREAM(buf, obex_push, sizeof(obex_push))
                UINT8_TO_STREAM(buf, 0);

                send = 1;
            }
            // PnP Information request
            else if (packet[17] == 0x12 && packet[18] == 0x00)
            {
                pack_len = 73;
                UINT8_TO_STREAM(buf, pack_len / 256);
                UINT8_TO_STREAM(buf, pack_len % 256);
                UINT8_TO_STREAM(buf, H4_TYPE_ACL);
                UINT16_TO_STREAM(buf, acl_flags);
                UINT16_TO_STREAM(buf, 68);

                UINT16_TO_STREAM(buf, 64);
                UINT16_TO_STREAM(buf, src_cid);
                UINT8_TO_STREAM(buf, 0x07);
                uint16_t txn_id = 256U * packet[11] + packet[10];
                UINT16_TO_STREAM(buf, txn_id);

                UINT16_TO_STREAM(buf, 0x3b00);
                UINT16_TO_STREAM(buf, 0x3800);
                uint8_t pnp[] =
                    {0x35, 0x36, 0x36, 0x00, 0x33, 0x09, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x02, 0x09, 0x00, 0x01,
                     0x35, 0x03, 0x19, 0x12, 0x00, 0x09, 0x02, 0x00, 0x09, 0x01, 0x03, 0x09, 0x02, 0x01, 0x09, 0x00,
                     0x75, 0x09, 0x02, 0x02, 0x09, 0x01, 0x00, 0x09, 0x02, 0x03, 0x09, 0x02, 0x01, 0x09, 0x02, 0x04,
                     0x28, 0x01, 0x09, 0x02, 0x05, 0x09, 0x00, 0x01};

                ARRAY_TO_STREAM(buf, pnp, sizeof(pnp));
                UINT8_TO_STREAM(buf, 0);

                send = 1;
            }
            break;
        }
    }
    if (send)
    {
        queue_packet(cmd_buf);
    }
}

void acl_event_handler(uint8_t *packet, uint16_t len)
{
    l2cap_cmd_handler(packet, len);
}

/*
 * Callback for controller recieved packet event
 * Triggered when esp_vhci_host_send_packet() is called in send()
 */
static void controller_rcv_pkt_ready(void)
{
    if (DEBUG)
    {
        ESP_LOGI(tag, "Controller recieved packet.");
    }
}

/*
 * BT controller callback function, to transfer data packet to upper layer.
 *         controller is ready to receive command
 * Separate function calls for HCI and ACL packets
 */
static int host_rcv_pkt(uint8_t *data, uint16_t len)
{
    if (DEBUG)
    {
        ESP_LOGI(tag, "Host recieved packet :");
        for (uint16_t i = 0; i < ((len > 30) ? 30 : len); i++)
        {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }
    if (data[0] == 0x04) // HCI packet
        hci_event_handler(data, len);
    else if (data[0] == 0x02) // ACL packet
        acl_event_handler(data, len);
    return 0;
}

// Callback function struct
static esp_vhci_host_callback_t vhci_host_cb = {
    controller_rcv_pkt_ready,
    host_rcv_pkt};

typedef uint8_t bd_addr_t[BD_ADDR_LEN]; /* Device address */

static uint8_t hci_cmd_buf[MAX_CMD_LEN];

// Resets the bluetooth controller state
static uint16_t make_cmd_reset(uint8_t *buf)
{
    UINT8_TO_STREAM(buf, HCI_H4_CMD_PREAMBLE_SIZE / 256);
    UINT8_TO_STREAM(buf, HCI_H4_CMD_PREAMBLE_SIZE % 256);
    UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM(buf, HCI_RESET);
    UINT8_TO_STREAM(buf, 0);
    return HCI_H4_CMD_PREAMBLE_SIZE;
}

// Changes the device name to "tag"
uint16_t make_cmd_chanage_local_name(uint8_t *buf, uint8_t *name)
{
    UINT8_TO_STREAM(buf, (HCI_H4_CMD_PREAMBLE_SIZE + 248) / 256);
    UINT8_TO_STREAM(buf, (HCI_H4_CMD_PREAMBLE_SIZE + 248) % 256);
    UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM(buf, HCI_CHANGE_LOCAL_NAME);
    UINT8_TO_STREAM(buf, 248);
    ARRAY_TO_STREAM(buf, name, strlen((const char *)name));
    return HCI_H4_CMD_PREAMBLE_SIZE + 248;
}

// Sets the scan mode for the radio
uint16_t make_cmd_set_scan_mode(uint8_t *buf, uint8_t scan_mode)
{
    UINT8_TO_STREAM(buf, (HCI_H4_CMD_PREAMBLE_SIZE + 1) / 256);
    UINT8_TO_STREAM(buf, (HCI_H4_CMD_PREAMBLE_SIZE + 1) % 256);
    UINT8_TO_STREAM(buf, H4_TYPE_COMMAND);
    UINT16_TO_STREAM(buf, HCI_SET_SCAN_MODE);
    UINT8_TO_STREAM(buf, 1);
    UINT8_TO_STREAM(buf, scan_mode);
    return HCI_H4_CMD_PREAMBLE_SIZE + 1;
}
static void hci_cmd_send_reset(void)
{
    make_cmd_reset(hci_cmd_buf);
    queue_packet(hci_cmd_buf);
}
static void hci_cmd_send_change_local_name(void)
{
    make_cmd_chanage_local_name(hci_cmd_buf, (uint8_t *)tag);
    queue_packet(hci_cmd_buf);
}

static void hci_cmd_send_set_scan_mode(void)
{
    uint8_t scan_mode = 3; // inquiry scan & page scan enable
    make_cmd_set_scan_mode(hci_cmd_buf, scan_mode);
    queue_packet(hci_cmd_buf);
}

/*
 * send HCI commands to perform BT advertising;
 * Reset controller, change name and set scan mode
 */
void btAdvtTask(void *pvParameters)
{
    int cmd_cnt = 0;
    bool send_avail = false;

    printf("BT advt task start\n");
    while (1)
    {
        vTaskDelay(100 / portTICK_PERIOD_MS);
        send_avail = esp_vhci_host_check_send_available();
        if (send_avail)
        {
            switch (cmd_cnt)
            {
            case 0:
                hci_cmd_send_reset();
                ++cmd_cnt;
                printf("BT Advertise, flag_send_avail: %d, cmd_sent: %d\n", send_avail, cmd_cnt);
                break;
            case 1:
                hci_cmd_send_change_local_name();
                ++cmd_cnt;
                printf("BT Advertise, flag_send_avail: %d, cmd_sent: %d\n", send_avail, cmd_cnt);
                break;
            case 2:
                hci_cmd_send_set_scan_mode();
                ++cmd_cnt;
                printf("BT Advertise, flag_send_avail: %d, cmd_sent: %d\n", send_avail, cmd_cnt);
                break;
            }
        }
    }
}

// code originated in esp32-hal-bt.c: bool btStart(void)
static bool start_bt(void)
{
    esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED)
    {
        return true;
    }
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE)
    {
        esp_bt_controller_init(&cfg);
        while (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE)
            ;
    }
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_INITED)
    {

#ifdef CONFIG_BTDM_CTRL_MODE_BTDM // If dual mode enble BLE also
        if (esp_bt_controller_enable(ESP_BT_MODE_CLASSIC_BT | ESP_BT_MODE_BLE))
        {
            ESP_LOGE(tag, "BT Enable failed");
            return false;
        }
#endif

#ifdef CONFIG_BTDM_CTRL_MODE_BR_EDR_ONLY
        if (esp_bt_controller_enable(ESP_BT_MODE_CLASSIC_BT))
        {
            ESP_LOGE(tag, "BT Enable failed");
            return false;
        }
#endif

#ifdef CONFIG_BTDM_CTRL_MODE_BLE_ONLY
        ESP_LOGE(tag, "Please enable BR/EDR mode");
        return false;
#endif
    }
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED)
    {
        return true;
    }
    ESP_LOGE(tag, "BT Start failed");
    return false;
}

void init_bt()
{
    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Release BLE memory

#ifdef CONFIG_BTDM_CTRL_MODE_BR_EDR_ONLY // Release BLE memory only if controller is set to BR/EDR only
    ret = esp_bt_controller_mem_release(ESP_BT_MODE_BLE);
    if (ret)
    {
        ESP_LOGW(tag, "Bluetooth controller release ble memory failed, skipping");
    }
#endif

    // Start BT
    if (!start_bt())
    {
        ESP_LOGE(tag, "Bluetooth controller enable failed");
        return;
    }
    // Register the host and controller callbacks
    esp_vhci_host_register_callback(&vhci_host_cb);
    // Initialize the send queue(may fail and restart the chip)
    init_queue();
    // Create and start send task
    xTaskCreatePinnedToCore(&send, "send", 2048, NULL, 5, NULL, 1);
    // Create and start advert task
    xTaskCreatePinnedToCore(&btAdvtTask, "btAdvtTask", 2048, NULL, 5, NULL, 1);
}
