#ifndef SUNK_SPOOF_H
#define SUNK_SPOOF_H
#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>
#pragma pack(1)
// Global Datastructure
typedef struct __tagPcapChannel
{
    pcap_t *wlanDevice;
    pcap_t *vEtherDevice;
} PcapChannel;
typedef struct __tagMachineInfo
{
    uint8_t MacAddress[6];
    uint32_t IpAddress;
} MachineInfo;
typedef struct __tagConnectionStatus
{
    uint32_t destIp;       // original Ip for it
    uint8_t state;         // 0-closed,1-half_closed,2-connecting
    uint32_t halfCloseSeq; // next FIN should have ACK of halfCloseSeq+1
} ConnectionStatus;
typedef struct __tagSpoofSession
{
    MachineInfo machineInfo;
    PcapChannel forwardChannel;
    PcapChannel backwardChannel;
    HANDLE hSpoofThread;
    HANDLE hForwardThread;
    HANDLE hBackwardThread;
    bool exitFlag;
    SRWLOCK rwLock;
    ConnectionStatus connections[65536];
} SpoofSession;

#define MAX_MACHINES 2
extern int spoofSessionTop;
extern SpoofSession spoofSessions[MAX_MACHINES];
SpoofSession *CreateSpoofSession(uint8_t *targetMac, uint32_t targetIp);
void ShutdownSpoofSession(SpoofSession *session);
#endif