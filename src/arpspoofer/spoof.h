#ifndef SUNK_SPOOF_H
#define SUNK_SPOOF_H
#include "stdint.h"
#pragma pack(1)
typedef struct _tagMachineInfo
{
    uint8_t MacAddress[6];
    uint32_t IpAddress;
} MachineInfo;

void CreateSpoofThread(uint8_t *targetMac, uint32_t targetIp);
void ShutdownSpoofThreads();

#define MAX_MACHINES 2

extern unsigned int spoofedTop;
extern MachineInfo spoofedMachines[MAX_MACHINES];
#endif