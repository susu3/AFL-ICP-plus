#include "recorder.h"
#include "wire_format.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef struct { unsigned char *data; uint32_t length, sent; uint16_t status, flags; uint64_t time; } request_t;
typedef struct { unsigned char *data; uint32_t length, flags; int32_t after, status; uint64_t time; } window_t;
static request_t *requests;
static window_t *windows;
static uint32_t request_count, window_count;
static uint64_t execution_id, sample_count, interval, maximum, begin_time, end_time, used_bytes;
static int connection = -1, failed, save_bitmap;

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts)) return 0;
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static uint64_t setting(const char *name, uint64_t fallback) {
  const char *value = getenv(name);
  char *end;
  unsigned long long number;
  if (!value) return fallback;
  errno = 0; number = strtoull(value, &end, 10);
  if (errno || !*value || *end || *value == '-') { failed = 1; return 0; }
  return number;
}
static int reserve_bytes(uint64_t amount) {
  if (amount > maximum || used_bytes > maximum - amount) { failed = 1; return 0; }
  used_bytes += amount;
  return 1;
}
static void clear_record(void) {
  uint32_t i;
  for (i = 0; i < request_count; i++) free(requests[i].data);
  for (i = 0; i < window_count; i++) free(windows[i].data);
  free(requests); free(windows); requests = NULL; windows = NULL;
  request_count = window_count = 0; used_bytes = 56;
}
int icp_recorder_init(void) {
  const char *path = getenv("AFLICP_EVIDENCE_SOCKET");
  struct sockaddr_un address;
  int size;
  if (!path) return 0;
  memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(address.sun_path)) return -1;
  strcpy(address.sun_path, path);
  interval = setting("AFLICP_SAMPLE_INTERVAL", 1000);
  maximum = setting("AFLICP_MAX_RECORD_BYTES", 16777216);
  execution_id = setting("AFLICP_EXECUTION_START", 0);
  sample_count = setting("AFLICP_SAMPLE_START", 0);
  save_bitmap = setting("AFLICP_SAVE_BITMAP", 1) != 0;
  size = (int)setting("AFLICP_QUEUE_BYTES", 1048576);
  if (failed || maximum < 76 || size <= 0) return -1;
  connection = socket(AF_UNIX, SOCK_STREAM, 0);
  if (connection < 0 || fcntl(connection, F_SETFD, FD_CLOEXEC) ||
      setsockopt(connection, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) ||
      connect(connection, (struct sockaddr *)&address, sizeof(address))) return -1;
#ifdef SO_NOSIGPIPE
  { int yes = 1; setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)); }
#endif
  return 0;
}
void icp_recorder_begin(void) {
  if (connection < 0) return;
  clear_record(); ++execution_id; begin_time = now_ns(); end_time = 0;
}
void icp_recorder_request(const void *bytes, uint32_t length) {
  request_t *next, *r;
  if (connection < 0 || failed || !reserve_bytes((uint64_t)length + 20)) return;
  next = realloc(requests, ((size_t)request_count + 1) * sizeof(*requests));
  if (!next) { failed = 1; return; } requests = next;
  r = &requests[request_count++]; memset(r, 0, sizeof(*r));
  r->data = malloc(length ? length : 1);
  if (!r->data) { failed = 1; return; }
  memcpy(r->data, bytes, length); r->length = length;
  r->sent = ICP_UNKNOWN_U32; r->flags = ICP_FLAG_TIME_UNKNOWN | ICP_FLAG_SENT_UNKNOWN;
}
void icp_recorder_sent(uint32_t index, int sent) {
  request_t *r;
  if (connection < 0 || failed || index >= request_count) return;
  r = &requests[index]; r->time = now_ns(); r->flags = r->time ? 0 : ICP_FLAG_TIME_UNKNOWN;
  if (sent < 0) { r->status = ICP_SEND_ERROR; r->flags |= ICP_FLAG_SENT_UNKNOWN; }
  else { r->sent = sent; r->status = (uint32_t)sent == r->length ? ICP_SEND_COMPLETE : ICP_SEND_PARTIAL; }
}
void icp_recorder_window(int32_t after, int status, const void *data, uint32_t length, int tail) {
  window_t *next, *w;
  if (connection < 0 || failed || !reserve_bytes((uint64_t)length + 24)) return;
  next = realloc(windows, ((size_t)window_count + 1) * sizeof(*windows));
  if (!next) { failed = 1; return; } windows = next;
  w = &windows[window_count++]; memset(w, 0, sizeof(*w));
  w->data = malloc(length ? length : 1);
  if (!w->data) { failed = 1; return; }
  if (length) memcpy(w->data, data, length);
  w->length = length; w->after = after; w->status = status; w->time = now_ns();
  w->flags = (tail ? ICP_WINDOW_TAIL : 0) | (w->time ? 0 : ICP_FLAG_TIME_UNKNOWN);
}
void icp_recorder_end(void) { if (connection >= 0) end_time = now_ns(); }
static void put(unsigned char **p, uint64_t value, unsigned int width) {
  unsigned int i; for (i = 0; i < width; i++) { *(*p)++ = value & 255; value >>= 8; }
}
static int transmit(const void *data, size_t length) {
  const unsigned char *p = data;
  while (length) {
#ifdef MSG_NOSIGNAL
    ssize_t n = send(connection, p, length, MSG_NOSIGNAL);
#else
    ssize_t n = send(connection, p, length, 0);
#endif
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += n; length -= n;
  }
  return 0;
}
int icp_recorder_commit(unsigned int novelty, const unsigned int *states, uint32_t count, const void *bitmap, uint32_t bitmap_size) {
  uint32_t i, triggers;
  unsigned char header[20], *p, *frame;
  if (connection < 0) return 0;
  if (failed) return -1;
  ++sample_count;
  triggers = (novelty == 2 ? ICP_TRIGGER_NEW : 0) | (interval && sample_count % interval == 0 ? ICP_TRIGGER_PERIODIC : 0);
  if (!triggers) return 0;
  if (!save_bitmap) bitmap_size = 0;
  if (!reserve_bytes((uint64_t)count * 4 + bitmap_size) || used_bytes > SIZE_MAX || used_bytes > maximum - 20) return -1;
  frame = malloc((size_t)used_bytes); if (!frame) return -1;
  p = frame;
  put(&p, execution_id, 8); put(&p, execution_id, 8); put(&p, triggers, 4);
  put(&p, novelty, 1); put(&p, 0, 1); put(&p, 0, 2);
  put(&p, begin_time, 8); put(&p, end_time, 8);
  put(&p, request_count, 4); put(&p, window_count, 4); put(&p, count, 4); put(&p, bitmap_size, 4);
  for (i = 0; i < request_count; i++) {
    request_t *r = &requests[i]; put(&p, r->length, 4); put(&p, r->sent, 4); put(&p, r->status, 2); put(&p, r->flags, 2); put(&p, r->time, 8);
    memcpy(p, r->data, r->length); p += r->length;
  }
  for (i = 0; i < window_count; i++) {
    window_t *w = &windows[i]; put(&p, (uint32_t)w->after, 4); put(&p, (uint32_t)w->status, 4); put(&p, w->length, 4); put(&p, w->flags, 4); put(&p, w->time, 8);
    memcpy(p, w->data, w->length); p += w->length;
  }
  for (i = 0; i < count; i++) put(&p, states[i], 4);
  if (bitmap_size) memcpy(p, bitmap, bitmap_size);
  p = header; memcpy(p, ICP_MAGIC, 8); p += 8; put(&p, 1, 2); put(&p, 0, 2); put(&p, used_bytes, 8);
  i = transmit(header, sizeof(header)) || transmit(frame, (size_t)used_bytes);
  free(frame);
  return i ? -1 : 0;
}
int icp_recorder_finish(void) {
  const char *path = getenv("AFLICP_COUNTER_PATH");
  int result = 0;
  if (connection >= 0) {
    unsigned char header[20], *p = header;
    char ack = 0;
    memcpy(p, ICP_MAGIC, 8); p += 8; put(&p, 1, 2); put(&p, 0, 2); put(&p, 0, 8);
    if (transmit(header, sizeof(header)) || recv(connection, &ack, 1, 0) != 1 || ack != 'K') result = -1;
    close(connection); connection = -1;
    if (path) {
      size_t length = strlen(path);
      char *temporary = malloc(length + 32);
      FILE *stream = NULL;
      if (!temporary) result = -1;
      else {
        snprintf(temporary, length + 32, "%s.tmp.%ld", path, (long)getpid());
        stream = fopen(temporary, "w");
        if (!stream) result = -1;
        else {
          if (fprintf(stream, "{\"execution_id\":%llu,\"sample_count\":%llu}\n",
                      (unsigned long long)execution_id, (unsigned long long)sample_count) < 0 ||
              fflush(stream) || fsync(fileno(stream))) result = -1;
          if (fclose(stream)) result = -1;
          if (!result && rename(temporary, path)) result = -1;
        }
        if (result) unlink(temporary);
        free(temporary);
      }
    }
  }
  clear_record(); return result;
}
