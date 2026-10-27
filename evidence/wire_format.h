#ifndef AFLICP_WIRE_FORMAT_H
#define AFLICP_WIRE_FORMAT_H
#include <stdint.h>
#define ICP_MAGIC "AICPEV01"
#define ICP_WIRE_VERSION 1
#define ICP_UNKNOWN_U32 UINT32_MAX
#define ICP_TRIGGER_NEW 1u
#define ICP_TRIGGER_PERIODIC 2u
#define ICP_FLAG_TIME_UNKNOWN 1u
#define ICP_FLAG_SENT_UNKNOWN 2u
#define ICP_WINDOW_TAIL 4u
#define ICP_SEND_NOT_ATTEMPTED 0u
#define ICP_SEND_COMPLETE 1u
#define ICP_SEND_PARTIAL 2u
#define ICP_SEND_ERROR 3u
/* Receive status is the observed net_recv wrapper result: 0 success (may be
 * empty/poll timeout), 1 error. It is deliberately NOT an errno or TCP causal ID. */
#endif
