#include "globals.h"

const char const *WLAN_DEVICE_DESCR = "";
char wlanDeviceStorage[PATH_MAX];
const char const *WLAN_DEVICE_NAME = "\\Device\\NPF_{29F6B571-59B8-4673-944F-F80EA9E5770C}";
const char const *VETHER_DEVICE_DESCR = "Hyper-V Virtual Ethernet Adapter #3";
char vEtherDeviceStorage[PATH_MAX];
const char const *VETHER_DEVICE_NAME = vEtherDeviceStorage;
void SetWlanDeviceName(char *name)
{
    strcpy(wlanDeviceStorage, "\\Device\\NPF_");
    strcat(wlanDeviceStorage, name);
}
void SetVEtherDeviceName(char *name)
{
    strcpy(vEtherDeviceStorage, "\\Device\\NPF_");
    strcat(vEtherDeviceStorage, name);
}

unsigned long ipAddr, gateAddr, wlanMask;
unsigned long ipWslHost, ipWsl, wslMask;
unsigned char localMacAddr[6], gateMacAddr[6];
unsigned char wslHostAddr[MACADDR_LEN], wslAddr[MACADDR_LEN];

uint8_t *dumpDevice;