#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lwmqtt/posix.h>

#define COMMAND_TIMEOUT 5000
#define MESSAGE_TIMEOUT 1000

lwmqtt_posix_network_t network = {0};

lwmqtt_posix_timer_t timer1, timer2, timer3;

lwmqtt_client_t client;

static void message_arrived(lwmqtt_client_t *_client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg) {
  printf("message_arrived: %.*s => %.*s (%d)\n", (int)topic.len, topic.data, (int)msg.payload_len, (char *)msg.payload,
         (int)msg.payload_len);
}

int main(void) {
  // initialize client
  lwmqtt_init(&client, malloc(512), 512, malloc(512), 512);

  // configure client
  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, NULL, message_arrived);

  // configure message time
  lwmqtt_posix_timer_set(&timer3, MESSAGE_TIMEOUT);

  // connect to broker
  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, "public.cloud.shiftr.io", 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_posix_network_connect: %d\n", err);
    exit(1);
  }

  // prepare options
  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.clean_session = false;
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");
  options.keep_alive = 5;

  // send connect packet
  err = lwmqtt_connect(&client, &options, NULL, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, options.return_code);
    exit(1);
  }

  // log
  printf("connected! (session present: %d)\n", options.session_present);

  // subscribe to topic
  err = lwmqtt_subscribe_one(&client, lwmqtt_string("hello"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_subscribe: %d\n", err);
    exit(1);
  }

  // loop forever
  for (;;) {
    // check if data is available
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_posix_network_peek: %d\n", err);
      exit(1);
    }

    // process data if available
    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_yield: %d\n", err);
        exit(1);
      }
    }

    // keep connection alive
    err = lwmqtt_keep_alive(&client, COMMAND_TIMEOUT);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_keep_alive: %d\n", err);
      exit(1);
    }

    // check if message is due
    if (lwmqtt_posix_timer_get(&timer3) <= 0) {
      // prepare message
      lwmqtt_message_t msg = {.qos = LWMQTT_QOS0, .retained = false, .payload = (uint8_t *)("world"), .payload_len = 5};

      // publish message
      err = lwmqtt_publish(&client, NULL, lwmqtt_string("hello"), msg, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_keep_alive: %d\n", err);
        exit(1);
      }

      // reset timer
      lwmqtt_posix_timer_set(&timer3, MESSAGE_TIMEOUT);
    }

    // sleep for 100ms
    usleep(100 * 1000);
  }
}
