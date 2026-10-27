#include <string.h>
#include "registry.h"
#include "active_registry.inc"
const aflnet_protocol_adapter_t *aflnet_protocol_lookup(const char *name) {
  unsigned int i;
  for (i = 0; i < sizeof(adapters) / sizeof(adapters[0]); i++)
    if (!strcmp(name, adapters[i].protocol_name)) return &adapters[i];
  return 0;
}
