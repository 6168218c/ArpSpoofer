#ifndef SUNK_CHANNELLING_H
#define SUNK_CHANNELLING_H
#include <pcap.h>
#include "spoof.h"
void create_forward_channel(SpoofSession *session);
void create_backward_channel(SpoofSession *session);
void run_forward_loop(SpoofSession *session);
void run_backward_loop(SpoofSession *session);
#endif