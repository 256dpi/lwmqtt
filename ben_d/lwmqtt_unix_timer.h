#ifndef LWMQTT_UNIX_TIMER_H
#define LWMQTT_UNIX_TIMER_H

#include <stdint.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The UNIX timer object.
 */
typedef struct {
  struct timeval end;
} lwmqtt_unix_timer_t;

/**
 * Callback to set the UNIX timer object.
 *
 * @see lwmqtt_timer_set_t.
 */
void lwmqtt_unix_timer_set(void *ref, uint32_t timeout);

/**
 * Callback to read the UNIX timer object.
 *
 * @see lwmqtt_timer_get_t.
 */
int32_t lwmqtt_unix_timer_get(void *ref);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // LWMQTT_UNIX_TIMER_H
