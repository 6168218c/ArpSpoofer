#ifndef SUNK_GLOBALS_H
#define SUNK_GLOBALS_H
#include <stdbool.h>
#include <pcap.h>
extern const char const *WLAN_DEVICE_NAME;
extern const char const *VETHER_DEVICE_NAME;
extern unsigned long ipAddr, gateAddr;
extern unsigned long ipWslHost, ipWsl;
#define MACADDR_LEN 6
extern unsigned char localMacAddr[MACADDR_LEN], gateMacAddr[MACADDR_LEN];
extern unsigned char wslHostAddr[MACADDR_LEN], wslAddr[MACADDR_LEN];

#ifdef _DEBUG
#define LOG(args...) \
    printf(args);    \
    printf("\n");
#else
#define LOG(args...)
#endif

#endif