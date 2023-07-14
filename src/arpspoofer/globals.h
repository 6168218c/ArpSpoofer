#ifndef SUNK_GLOBALS_H
#define SUNK_GLOBALS_H
#include <stdbool.h>
#include <pcap.h>
extern const char const *WLAN_DEVICE_DESCR;
extern const char const *WLAN_DEVICE_NAME;
extern const char const *VETHER_DEVICE_DESCR;
extern const char const *VETHER_DEVICE_NAME;
void SetWlanDeviceName(char * name);
void SetVEtherDeviceName(char * name);


extern unsigned long ipAddr, gateAddr, wlanMask;
extern unsigned long ipWslHost, ipWsl, wslMask;
#define MACADDR_LEN 6
#define SSLSERVER_PORT 27013
extern unsigned char localMacAddr[MACADDR_LEN], gateMacAddr[MACADDR_LEN];
extern unsigned char wslHostAddr[MACADDR_LEN], wslAddr[MACADDR_LEN];

#ifdef _DEBUG
extern uint8_t *dumpDevice;
#define LOGDEBUG(args...) \
    printf(args);         \
    printf("\n");
#else
#define LOGDEBUG(args...)
#endif
#define LOG(args...) \
    printf(args);    \
    printf("\n");
#endif