#ifndef AFLICP_RECORDER_H
#define AFLICP_RECORDER_H
#include <stdint.h>
int icp_recorder_init(void);
void icp_recorder_begin(void);
void icp_recorder_request(const void *bytes, uint32_t length);
void icp_recorder_sent(uint32_t index, int sent);
void icp_recorder_window(int32_t after, int status, const void *data, uint32_t length, int tail);
void icp_recorder_end(void);
int icp_recorder_commit(unsigned int novelty, const unsigned int *states, uint32_t count, const void *bitmap, uint32_t bitmap_size);
int icp_recorder_finish(void);
#endif
