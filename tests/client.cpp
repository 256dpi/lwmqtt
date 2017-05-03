#include <gtest/gtest.h>

extern "C" {
#include <lwmqtt.h>
#include <lwmqtt/unix.h>
}

#define COMMAND_TIMEOUT 5000

#define PAYLOAD_LEN 256
char payload[PAYLOAD_LEN + 1];

volatile int counter;

const char *custom_ref = "cool";

static void message_arrived(lwmqtt_client_t *c, void *ref, lwmqtt_string_t *t, lwmqtt_message_t *m) {
  ASSERT_EQ(ref, custom_ref);

  int res = lwmqtt_strcmp(t, (char *)"lwmqtt");
  ASSERT_EQ(res, 0);

  res = strncmp(payload, (char *)m->payload, (size_t)m->payload_len);
  ASSERT_EQ(res, 0);

  counter++;
}

TEST(Client, PublishSubscribeQOS0) {
  unsigned char buf1[512], buf2[512];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, (char *)"broker.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id = lwmqtt_str("lwmqtt");
  data.username = lwmqtt_str("try");
  data.password = lwmqtt_str("try");

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe(&client, "lwmqtt", LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS0;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, "lwmqtt", &msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    int available = 0;
    err = lwmqtt_unix_network_peek(&client, &network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe(&client, "lwmqtt", COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_unix_network_disconnect(&network);
}

TEST(Client, PublishSubscribeQOS1) {
  unsigned char buf1[512], buf2[512];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, (char *)"broker.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id = lwmqtt_str("lwmqtt");
  data.username = lwmqtt_str("try");
  data.password = lwmqtt_str("try");

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe(&client, "lwmqtt", LWMQTT_QOS1, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS1;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, "lwmqtt", &msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    int available = 0;
    err = lwmqtt_unix_network_peek(&client, &network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe(&client, "lwmqtt", COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_unix_network_disconnect(&network);
}

TEST(Client, PublishSubscribeQOS2) {
  unsigned char buf1[512], buf2[512];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 512);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, (char *)"broker.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id = lwmqtt_str("lwmqtt");
  data.username = lwmqtt_str("try");
  data.password = lwmqtt_str("try");

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe(&client, "lwmqtt", LWMQTT_QOS2, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS2;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, "lwmqtt", &msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    int available = 0;
    err = lwmqtt_unix_network_peek(&client, &network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe(&client, "lwmqtt", COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_unix_network_disconnect(&network);
}

TEST(Client, BufferOverflowProtection) {
  unsigned char buf1[512], buf2[256];

  lwmqtt_unix_network_t network;
  lwmqtt_unix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, buf1, 512, buf2, 256);

  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, (char *)"broker.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_options_t data = lwmqtt_default_options;
  data.client_id = lwmqtt_str("lwmqtt");
  data.username = lwmqtt_str("try");
  data.password = lwmqtt_str("try");

  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, &data, NULL, &return_code, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe(&client, "lwmqtt", LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS0;
  msg.payload = payload;
  msg.payload_len = PAYLOAD_LEN;

  err = lwmqtt_publish(&client, "lwmqtt", &msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  while (counter < 1) {
    int available = 0;
    err = lwmqtt_unix_network_peek(&client, &network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
      break;
    }
  }

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_unix_network_disconnect(&network);
}
