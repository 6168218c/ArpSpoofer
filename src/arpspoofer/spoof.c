#include "pcap.h"
#include "windows.h"
#include "spoof.h"
#include "packet.h"
#include "globals.h"
#include "channelling.h"
#include "windows.h"
#include "synchapi.h"

int spoofSessionTop;
SpoofSession spoofSessions[MAX_MACHINES];

static ULONG SpoofThreadProc(LPVOID lpParams)
{
    SpoofSession *session = lpParams;
    char errbuf[PCAP_BUF_SIZE];
    pcap_t *subDevice = pcap_open(WLAN_DEVICE_NAME, 65536, 0, 0, NULL, errbuf);
    pcap_t *wslDevice = pcap_open(VETHER_DEVICE_NAME, 65536, 0, 0, NULL, errbuf);
    ArpPacket pktMem;
    ArpPacket *arpPacket = &pktMem;
    while (!session->exitFlag)
    {
        SetupArpPacket(arpPacket, localMacAddr, session->machineInfo.MacAddress, gateAddr,
                       session->machineInfo.IpAddress, 2);
        pcap_sendpacket(subDevice, (const uint8_t *)arpPacket, sizeof(ArpPacket));
        SetupArpPacket(arpPacket, wslHostAddr, wslAddr, session->machineInfo.IpAddress, ipWsl, 2);
        pcap_sendpacket(wslDevice, (const uint8_t *)arpPacket, sizeof(ArpPacket));
        Sleep(500);
    }
    pcap_close(subDevice);
    pcap_close(wslDevice);
}

SpoofSession *CreateSpoofSession(uint8_t *targetMac, uint32_t targetIp)
{
    if (spoofSessionTop >= MAX_MACHINES)
    {
        return NULL;
    }

    DWORD threadId;
    SpoofSession *session = &spoofSessions[spoofSessionTop];
    memset(session, 0, sizeof(SpoofSession));
    memcpy(session->machineInfo.MacAddress, targetMac, MACADDR_LEN);
    session->machineInfo.IpAddress = targetIp;
    if (!(session->hSpoofThread = CreateThread(NULL, 0, SpoofThreadProc, session, 0, &threadId)))
    {
        LOG("Spoof thread on MAC %.2x%.2x%.2x%.2x%.2x%.2x failed to start!",
            targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5])
        return NULL;
    }
    LOG("Spoof thread on MAC %.2x%.2x%.2x%.2x%.2x%.2x started",
        targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5])
    //Create Channels
    create_forward_channel(session);
    create_backward_channel(session);
    InitializeSRWLock(&session->rwLock);
    run_forward_loop(session);
    run_backward_loop(session);
}

void ShutdownSpoofSession(SpoofSession *session)
{
    session->exitFlag = true;
    HANDLE arr[] = {session->hBackwardThread, session->hForwardThread, session->hSpoofThread};
    WaitForMultipleObjects(3, arr, true, -1);
    pcap_close(session->forwardChannel.vEtherDevice);
    pcap_close(session->forwardChannel.wlanDevice);
    pcap_close(session->backwardChannel.vEtherDevice);
    pcap_close(session->backwardChannel.wlanDevice);
}