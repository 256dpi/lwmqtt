#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/client.h"
#include "unix.h"

char *topic = "hello";

#define PAYLOAD_LEN 256
char payload[PAYLOAD_LEN + 1];

volatile int counter;

static void message_arrived(lwmqtt_client_t *c, lwmqtt_string_t *t, lwmqtt_message_t *m) {
  if (lwmqtt_strcmp(t, topic) != 0) {
    printf("topic does not match\n");
    exit(1);
  }

  if (strncmp(payload, m->payload, (size_t)m->payload_len) != 0) {
    printf("payload does not match\n");
    exit(1);
  }

  counter++;
}

static void testSendAndReceive(lwmqtt_qos_t qos) {
  unsigned char buf1[512], buf2[512];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, "127.0.0.1", 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect: %d\n", err);
    exit(1);
  }

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id.c_string = "lwmqtt";

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, 1000);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, return_code);
    exit(1);
  }

  err = lwmqtt_subscribe(&client, "hello", qos, 1000);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_subscribe: %d\n", err);
    exit(1);
  }

  counter = 0;

  while (counter < 5) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = qos;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, "hello", &msg, 1000);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_publish: %d (%d)\n", err, counter);
      exit(1);
    }

    err = lwmqtt_yield(&client, 10);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_yield: %d (%d)\n", err, counter);
      exit(1);
    }
  }

  err = lwmqtt_unsubscribe(&client, "hello", 1000);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unsubscribe: %d\n", err);
    exit(1);
  }

  err = lwmqtt_disconnect(&client, 1000);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_disconnect: %d\n", err);
    exit(1);
  }

  lwmqtt_unix_network_disconnect(&network);
}

static void testKeepAlive() {
  unsigned char buf1[512], buf2[512];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, "127.0.0.1", 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect: %d\n", err);
    exit(1);
  }

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id.c_string = "lwmqtt";
  data.keep_alive = 5;

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, 1000);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, return_code);
    exit(1);
  }

  while (true) {
    err = lwmqtt_yield(&client, 10);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_yield: %d (%d)\n", err, counter);
      exit(1);
    }
  }
}

int main() {
  for (int i = 0; i < PAYLOAD_LEN; i++) {
    payload[i] = 'x';
  }

  payload[PAYLOAD_LEN] = 0;

  printf("Running QoS 0 tests...\n");
  testSendAndReceive(LWMQTT_QOS0);

  printf("Running QoS 1 tests...\n");
  testSendAndReceive(LWMQTT_QOS1);

  printf("Running QoS 2 tests...\n");
  testSendAndReceive(LWMQTT_QOS2);

  printf("Running Keep Alive test...\n");
  testKeepAlive();

  return 0;
}
