#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "alloc-inl.h"
#include "aflnet.h"
#include "protocols/registry.h"

int main(int argc, char **argv) {
  FILE *stream;
  long file_size;
  unsigned char *bytes;
  unsigned int regions_count = 0, states_count = 0, i;
  region_t *regions;
  unsigned int *states;
  const aflnet_protocol_adapter_t *adapter;
  if (argc != 3) {
    fprintf(stderr, "Usage: adapter-observe PROTOCOL RAW_INPUT_FILE\n");
    return 2;
  }
  adapter = aflnet_protocol_lookup(argv[1]);
  if (!adapter) { fprintf(stderr, "Unknown registered protocol: %s\n", argv[1]); return 2; }
  stream = fopen(argv[2], "rb");
  if (!stream) { perror("open input"); return 2; }
  if (fseek(stream, 0, SEEK_END) || (file_size = ftell(stream)) < 0 || fseek(stream, 0, SEEK_SET)) {
    fclose(stream); fprintf(stderr, "Cannot size input\n"); return 2;
  }
  if ((unsigned long)file_size > UINT_MAX) {
    fclose(stream); fprintf(stderr, "Input exceeds adapter ABI size limit\n"); return 2;
  }
  bytes = ck_alloc(file_size ? (unsigned int)file_size : 1);
  if (file_size && fread(bytes, 1, (unsigned int)file_size, stream) != (size_t)file_size) {
    fclose(stream); ck_free(bytes); fprintf(stderr, "Cannot read complete input\n"); return 2;
  }
  fclose(stream);
  init_message_code_map();
  regions = adapter->extract_requests(bytes, (unsigned int)file_size, &regions_count);
  states = adapter->extract_response_codes(bytes, (unsigned int)file_size, &states_count);
  if ((file_size && !regions_count) || (regions_count && !regions) || !states || !states_count) {
    fprintf(stderr, "Adapter returned missing parse results\n"); return 3;
  }
  for (i = 0; i < regions_count; ++i) {
    if (regions[i].start_byte < 0 || regions[i].end_byte < regions[i].start_byte ||
        (unsigned int)regions[i].end_byte >= (unsigned int)file_size) {
      fprintf(stderr, "Adapter returned out-of-buffer region %u\n", i); return 3;
    }
  }
  printf("{\"protocol\":\"%s\",\"input_bytes\":%ld,\"regions\":[", argv[1], file_size);
  for (i = 0; i < regions_count; ++i)
    printf("%s[%d,%d]", i ? "," : "", regions[i].start_byte, regions[i].end_byte);
  printf("],\"states\":[");
  for (i = 0; i < states_count; ++i) printf("%s%u", i ? "," : "", states[i]);
  puts("]}");
  if (regions) ck_free(regions);
  ck_free(states); ck_free(bytes); destroy_message_code_map();
  return 0;
}
