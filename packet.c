#include "packet.h"
#include "pcap.h"

// Packet Utilities
uint16_t Checksum(uint16_t *packet, int packlen)
{
    register unsigned long sum = 0;

    while (packlen > 1)
    {
        sum += *(packet++);
        packlen -= 2;
    }

    if (packlen > 0)
        sum += *(unsigned char *)packet;

    /* TODO: this depends on byte order */

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}
uint16_t TcpPacketLen(TcpPacket *tcpPacket)
{
    return ntohs(tcpPacket->ipv4.len) - sizeof(tcpPacket->ipv4);
}
uint16_t TcpChecksum(TcpPacket *tcpPacket)
{
    uint16_t len = TcpPacketLen(tcpPacket);
    uint8_t *buf = malloc(12 + len);
    // setup pseudo header
    memcpy(buf, &tcpPacket->ipv4.src, sizeof(uint32_t));
    memcpy(buf + 4, &tcpPacket->ipv4.dst, sizeof(uint32_t));
    buf[8] = 0;
    buf[9] = (tcpPacket->ipv4.proto);
    memcpy(buf + 10, &len, sizeof(uint16_t));
    buf[10] = (uint16_t)(len & 0xFF00) >> 8;
    buf[11] = (uint16_t)(len & 0x00FF);
    memcpy(buf + 12, &tcpPacket->tcp, len);
    ((tcp_header *)(buf + 12))->checksum = 0;
    uint16_t checksum = Checksum((uint16_t *)buf, 12 + len);
    free(buf);
    return checksum;
}

void SetupArpPacket(ArpPacket *packet, uint8_t *sourceMac, uint8_t *destMac,
                    uint32_t sourceIp, uint32_t destIp, uint16_t opcode)
{
    memcpy(packet->ether.ether_shost, sourceMac, 6);
    memcpy(packet->ether.ether_dhost, destMac, 6);
    packet->ether.ether_type = ntohs(0x0806); // ARP
    packet->arp.ar_hrd = ntohs(1);
    packet->arp.ar_pro = ntohs(0x0800); // IPV4
    packet->arp.ar_hln = 6;
    packet->arp.ar_pln = 4;
    packet->arp.ar_op = ntohs(opcode); // 1 for request,2 for reply
    memcpy(packet->arp.ar_sha, sourceMac, 6);
    packet->arp.ar_sip = sourceIp;
    memcpy(packet->arp.ar_tha, destMac, 6);
    packet->arp.ar_tip = destIp;
}