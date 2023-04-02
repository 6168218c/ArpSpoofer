#ifndef SUNK_GLOBALS_H
#define SUNK_GLOBALS_H
#include <stdbool.h>
extern const char *DEVICE_NAME;
extern unsigned long ipAddr, gateAddr;
extern unsigned char localMacAddr[6], gateMacAddr[6];

extern bool exitFlag;

#ifdef _DEBUG
#define LOG(args...) \
    printf(args);    \
    printf("\n");
#else
#define LOG(args...)
#endif

#endif