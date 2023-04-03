#ifndef SUNK_GLOBALS_H
#define SUNK_GLOBALS_H
#include <stdbool.h>
extern const char *DEVICE_NAME;
extern unsigned long ipAddr, gateAddr;
#define MACADDR_LEN 6
extern unsigned char localMacAddr[MACADDR_LEN], gateMacAddr[MACADDR_LEN];

extern bool exitFlag;

#ifdef _DEBUG
#define LOG(args...) \
    printf(args);    \
    printf("\n");
#else
#define LOG(args...)
#endif

#endif