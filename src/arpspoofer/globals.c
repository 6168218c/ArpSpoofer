#include "globals.h"

const char const *WLAN_DEVICE_NAME = "\\Device\\NPF_{29F6B571-59B8-4673-944F-F80EA9E5770C}";
const char const *VETHER_DEVICE_NAME = "\\Device\\NPF_{EC5744AA-D171-4167-B1A5-B628E7186147}";
unsigned long ipAddr, gateAddr, wlanMask;
unsigned long ipWslHost, ipWsl, wslMask;
unsigned char localMacAddr[6], gateMacAddr[6];
unsigned char wslHostAddr[MACADDR_LEN], wslAddr[MACADDR_LEN];

uint8_t *dumpDevice;