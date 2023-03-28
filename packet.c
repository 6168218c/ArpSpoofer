#include "pcap.h"
#include "ntddndis.h"
#include "iphlpapi.h"
#include "tchar.h"

#define LOG(args...) printf(args);

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

const char *DEVICE_NAME = "\\Device\\NPF_{29F6B571-59B8-4673-944F-F80EA9E5770C}";
unsigned long ipAddr, maskAddr, brdAddr, dstAddr;
unsigned char localMacAddr[6], gateMacAddr[6];

void init_addrs();
void init_macaddr(pcap_t *device);
void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

int main()
{
    pcap_t *dev;
    char errbuf[PCAP_BUF_SIZE];

    if (!LoadNpcapDlls())
    {
        printf("Failed to load Npcap!");
        exit(1);
    }

    init_addrs();

    pcap_t *pcap_handle = pcap_open(DEVICE_NAME, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
    if (pcap_handle == NULL)
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }
    init_macaddr(pcap_handle);

    if (pcap_loop(pcap_handle, -1, ethernet_protocol_callback, errbuf))
    {
        LOG("Failed:%s\n", errbuf)
        exit(1);
    }

    pcap_close(pcap_handle);
}

void init_addrs()
{
    /*pcap_if_t *allDevs;
    char errbuf[PCAP_BUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &allDevs, errbuf) == -1)
    {
        LOG("Failed:%s\n", errbuf);
        exit(1);
    }
    for (pcap_if_t *d = allDevs; d; d = d->next)
    {
        if (strstr(d->name, DEVICE_NAME) != NULL)
        {
            LOG("Interface found: %s", d->description)
            for (struct pcap_addr *address = d->addresses; address; address = address->next)
            {
                if (address->addr->sa_family == AF_INET)
                {
                    ipAddr = ((struct sockaddr_in *)address->addr)->sin_addr.s_addr;
                    if (address->broadaddr)
                    {
                        brdAddr = ((struct sockaddr_in *)address->broadaddr)->sin_addr.s_addr;
                    }
                    if (address->netmask)
                    {
                        maskAddr = ((struct sockaddr_in *)address->netmask)->sin_addr.s_addr;
                    }
                    if (address->dstaddr)
                    {
                        dstAddr = ((struct sockaddr_in *)address->dstaddr)->sin_addr.s_addr;
                    }
                }
            }
        }
    }
    pcap_freealldevs(allDevs);
    allDevs = NULL;*/
}

void init_macaddr(pcap_t *device)
{
    size_t len = 6;
    pcap_oid_get_request(device, OID_802_3_CURRENT_ADDRESS, localMacAddr, &len);

    ULONG size = 6;
    struct in_addr ad;
    ad.s_addr = brdAddr;
    printf(inet_ntoa(ad));
    SendARP(brdAddr, ipAddr, gateMacAddr, &size);

    if (len != 6 || size != 6)
    {
        LOG("Failed to obtain Mac Addresses!")
        exit(1);
    }
    LOG("Mac Addresses:\nLocal:%.2x%.2x%.2x%.2x%.2x%.2x\nGate:%.2x%.2x%.2x%.2x%.2x%.2x\n",
        localMacAddr[0], localMacAddr[1], localMacAddr[2], localMacAddr[3], localMacAddr[4], localMacAddr[5],
        gateMacAddr[0], gateMacAddr[1], gateMacAddr[2], gateMacAddr[3], gateMacAddr[4], gateMacAddr[5])
}

void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
}