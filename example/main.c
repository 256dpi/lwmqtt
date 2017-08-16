#include <stdio.h>
#include <stdlib.h>

#include <lwmqtt.h>
#include <lwmqtt/unix.h>

#define COMMAND_TIMEOUT 5000

static void message_arrived(lwmqtt_client_t *c, void *ref, lwmqtt_string_t *t, lwmqtt_message_t *m) {
  printf("message_arrived: %.*s => %.*s\n", (int)t->len, t->data, m->payload_len, (char *)m->payload);
}

int main() {
  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, malloc(512), 512, malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, NULL, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, "broker.shiftr.io", 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect: %d\n", err);
    exit(1);
  }

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id = lwmqtt_str("lwmqtt");
  data.username = lwmqtt_str("try");
  data.password = lwmqtt_str("try");
  data.keep_alive = 5;

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, return_code);
    exit(1);
  }

  printf("connected!\n");

  err = lwmqtt_subscribe_one(&client, "hello", LWMQTT_QOS0, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_subscribe: %d (%d)\n", err, return_code);
    exit(1);
  }

  while (true) {
    int available = 0;
    err = lwmqtt_unix_network_peek(&client, &network, &available);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_unix_network_peek: %d\n", err);
      exit(1);
    }

    if (available > 0) {
      err = lwmqtt_yield(&client, 0, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_yield: %d\n", err);
        exit(1);
      }
    }

    err = lwmqtt_keep_alive(&client, COMMAND_TIMEOUT);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_keep_alive: %d\n", err);
      exit(1);
    }
  }
}
