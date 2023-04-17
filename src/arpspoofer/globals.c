#include "globals.h"

const char const *WLAN_DEVICE_NAME = "\\Device\\NPF_{29F6B571-59B8-4673-944F-F80EA9E5770C}";
const char const *VETHER_DEVICE_NAME = "\\Device\\NPF_{04E2B72E-7DA0-44F1-AE2D-4C8B502ECC74}";
unsigned long ipAddr, gateAddr;
unsigned long ipWslHost, ipWsl;
unsigned char localMacAddr[6], gateMacAddr[6];
unsigned char wslHostAddr[MACADDR_LEN], wslAddr[MACADDR_LEN];

bool exitFlag = false;