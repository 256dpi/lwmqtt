#include <time.h>

#define __USE_GNU
#include <sys/time.h>

#include "lwmqtt_unix_timer.h"

static void get_current_time(struct timeval *now)
{
  struct timespec current_time;
  clock_gettime(CLOCK_MONOTONIC, &current_time);

  TIMESPEC_TO_TIMEVAL(now, &current_time);
}

void lwmqtt_unix_timer_set(void *ref, uint32_t timeout) {
  // cast timer reference
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  // clear end time
  timerclear(&t->end);

  // get current time
  struct timeval now;
  get_current_time(&now);

  // set future end time
  struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
  timeradd(&now, &interval, &t->end);
}

int32_t lwmqtt_unix_timer_get(void *ref) {
  // cast timer reference
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  // get current time
  struct timeval now;
  get_current_time(&now);

  // get difference to end time
  struct timeval res;
  timersub(&t->end, &now, &res);

  return (int32_t)((res.tv_sec * 1000) + (res.tv_usec / 1000));
}
