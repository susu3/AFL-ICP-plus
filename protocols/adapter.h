#ifndef AFLICP_ADAPTER_H
#define AFLICP_ADAPTER_H
#include "../types.h"
#include "../aflnet.h"
typedef region_t *(*aflnet_extract_requests_fn)(unsigned char *, unsigned int, unsigned int *);
typedef unsigned int *(*aflnet_extract_responses_fn)(unsigned char *, unsigned int, unsigned int *);
typedef struct {
  const char *protocol_name;
  aflnet_extract_requests_fn extract_requests;
  aflnet_extract_responses_fn extract_response_codes;
} aflnet_protocol_adapter_t;
#endif
