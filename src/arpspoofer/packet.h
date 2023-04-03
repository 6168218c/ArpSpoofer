/*
    Definations for packets
*/
#ifndef SUNK_PACKET_H
#define SUNK_PACKET_H
#include "stdint.h"

#pragma pack(1)

typedef struct
{
    unsigned char ether_dhost[6]; /* destination eth addr	*/
    unsigned char ether_shost[6]; /* source ether addr	*/
    unsigned short ether_type;    /* packet type ID field	*/
} ether_header;

typedef struct
{
    unsigned short ar_hrd;   //    硬件地址类型，以太网中为1
    unsigned short ar_pro;   //  协议地址类型，0x0800
    unsigned char ar_hln;    //    硬件地址长度，MAC地址的长度为6
    unsigned char ar_pln;    //    协议地址长度，IP地址的长度为4
    unsigned short ar_op;    //    ARP操作代码，1为请求，2为响应
    unsigned char ar_sha[6]; //    源MAC地址
    unsigned long ar_sip;    //    源IP地址
    unsigned char ar_tha[6]; //    目的MAC地址
    unsigned long ar_tip;    //    目的IP地址
} arp_header;

typedef struct
{
    uint8_t ver : 4;
    uint8_t hdr_len : 4;
    uint8_t dsc : 6;
    uint8_t esn : 2;
    uint16_t len;
    uint16_t id;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} ipv4_header;

typedef struct
{
    uint16_t src_port;    // 16位源端口号
    uint16_t dst_port;    // 16位目的端口号
    uint32_t seq;         // 32位序列号
    uint32_t ack_seq;     // 32位确认号
    uint8_t data_off_set; // 高4位表示数据偏移
    uint8_t flags;        // 6位标志位
    // FIN - 0x01
    // SYN - 0x02
    // RST - 0x04
    // PSH - 0x08
    // ACK - 0x10
    // URG - 0x20
    // ACE - 0x40
    // CWR - 0x80
    uint16_t window;   // 16位窗口大小
    uint16_t checksum; // 16位校验和
    uint16_t urgptr;   // 16位紧急数据偏移量
} tcp_header;

typedef struct
{
    ether_header header;
    uint8_t payload[0];
} EthernetPacket;

typedef struct
{
    ether_header ether;
    arp_header arp;
} ArpPacket;

typedef struct
{
    ether_header ether;
    ipv4_header ipv4;
    uint8_t payload[0];
} Ipv4Packet;

typedef struct
{
    ether_header ether;
    ipv4_header ipv4;
    tcp_header tcp;
    uint8_t payload[0];
} TcpPacket;

// Utility functions
uint16_t TcpPacketLen(TcpPacket *tcpPacket);
uint16_t TcpChecksum(TcpPacket *tcpPacket);
uint16_t Ipv4Checksum(Ipv4Packet *ipv4Packet);
void SetupArpPacket(ArpPacket *packet, uint8_t *sourceMac, uint8_t *destMac,
                    uint32_t sourceIp, uint32_t destIp, uint16_t opcode);

#endif