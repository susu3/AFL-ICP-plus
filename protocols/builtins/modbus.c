/* Modbus/TCP stream delimiting. Invalid/truncated tails are preserved for mutation.
 * This manually supplied baseline is NOT evidence of successful agent synthesis. */
#include "../../alloc-inl.h"
#include "../adapter.h"

region_t *aflicp_modbus_requests(unsigned char *buf, unsigned int size, unsigned int *count) {
  region_t *regions = 0;
  unsigned int offset = 0;
  *count = 0;
  if (!buf || !size) return 0;
  while (offset < size) {
    unsigned int length = size - offset;
    if (length >= 8) {
      unsigned int mbap_length = ((unsigned int)buf[offset + 4] << 8) | buf[offset + 5];
      if (!buf[offset + 2] && !buf[offset + 3] && mbap_length >= 2 && mbap_length <= length - 6)
        length = 6 + mbap_length;
    }
    regions = ck_realloc(regions, (*count + 1) * sizeof(*regions));
    memset(&regions[*count], 0, sizeof(*regions));
    regions[*count].start_byte = offset;
    regions[*count].end_byte = offset + length - 1;
    ++*count;
    offset += length;
  }
  return regions;
}

unsigned int *aflicp_modbus_responses(unsigned char *buf, unsigned int size, unsigned int *count) {
  unsigned int *states = ck_alloc(sizeof(*states));
  unsigned int offset = 0;
  states[0] = 0;  /* AFLNet's initial state, including no parseable response. */
  *count = 1;
  if (!buf) return states;
  while (size - offset >= 8) {
    unsigned int length = ((unsigned int)buf[offset + 4] << 8) | buf[offset + 5];
    unsigned int function = buf[offset + 7], state;
    if (buf[offset + 2] || buf[offset + 3] || length < 2 || length > size - offset - 6) break;
    if (!function) break;
    if (function & 128) {
      if (length < 3) break;
      /* Disjoint tag + exact function/exception tuple, not addition. */
      state = 0x10000u | (function << 8) | buf[offset + 8];
    } else state = function;
    states = ck_realloc(states, (*count + 1) * sizeof(*states));
    states[(*count)++] = state;
    offset += 6 + length;
  }
  return states;
}
