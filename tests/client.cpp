#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

extern "C" {
#include <lwmqtt.h>
#include <lwmqtt/posix.h>
}

#define COMMAND_TIMEOUT 5000

#define PAYLOAD_LEN 256
uint8_t payload[PAYLOAD_LEN + 1];

#define BIG_PAYLOAD_LEN 9800
uint8_t big_payload[BIG_PAYLOAD_LEN + 1];

volatile int counter;

const char *custom_ref = "cool";

static void message_arrived(lwmqtt_client_t *c, void *ref, lwmqtt_string_t t, lwmqtt_message_t m) {
  ASSERT_EQ(ref, custom_ref);

  int res = lwmqtt_strcmp(t, "lwmqtt");
  ASSERT_EQ(res, 0);

  ASSERT_EQ(m.payload_len, (size_t)PAYLOAD_LEN);
  res = memcmp(payload, (char *)m.payload, (size_t)m.payload_len);
  ASSERT_EQ(res, 0);

  counter++;
}

static void big_message_arrived(lwmqtt_client_t *c, void *ref, lwmqtt_string_t t, lwmqtt_message_t m) {
  ASSERT_EQ(ref, custom_ref);

  int res = lwmqtt_strcmp(t, "lwmqtt");
  ASSERT_EQ(res, 0);

  ASSERT_EQ(m.payload_len, (size_t)BIG_PAYLOAD_LEN);
  res = memcmp(big_payload, (char *)m.payload, (size_t)m.payload_len);
  ASSERT_EQ(res, 0);

  counter++;
}

TEST(Client, PublishSubscribeQOS0) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS0;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 5);
}

TEST(Client, PublishSubscribeQOS1) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS1, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS1;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 5);
}

TEST(Client, PublishSubscribeQOS2) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS2, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS2;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 5);
}

TEST(Client, BufferOverflow) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 256);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_string_t topic = {BIG_PAYLOAD_LEN, (char *)big_payload};
  lwmqtt_message_t msg = lwmqtt_default_message;

  err = lwmqtt_publish(&client, nullptr, topic, msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);

  counter = 0;

  msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS0;
  msg.payload = payload;
  msg.payload_len = PAYLOAD_LEN;

  err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  while (counter < 1) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
      break;
    }
  }

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 0);
}

TEST(Client, OverflowDropping) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 256);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  uint32_t dropped = 0;
  lwmqtt_drop_overflow(&client, true, &dropped);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS0;
  msg.payload = payload;
  msg.payload_len = PAYLOAD_LEN;

  err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  while (dropped < 2) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 0);
  ASSERT_EQ(dropped, 2);
}

TEST(Client, BigBuffersAndPayload) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(10000), 10000, (uint8_t *)malloc(10000), 10000);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, big_message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS0;
    msg.payload = big_payload;
    msg.payload_len = BIG_PAYLOAD_LEN;

    err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 5);
}

TEST(Client, MultipleSubscriptions) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_string_t topic_filters[2] = {lwmqtt_string("foo"), lwmqtt_string("lwmqtt")};
  lwmqtt_qos_t qos_levels[2] = {LWMQTT_QOS0, LWMQTT_QOS0};

  err = lwmqtt_subscribe(&client, 2, topic_filters, qos_levels, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  for (int i = 0; i < 5; i++) {
    lwmqtt_message_t msg = lwmqtt_default_message;
    msg.qos = LWMQTT_QOS0;
    msg.payload = payload;
    msg.payload_len = PAYLOAD_LEN;

    err = lwmqtt_publish(&client, nullptr, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
    ASSERT_EQ(err, LWMQTT_SUCCESS);
  }

  while (counter < 5) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe(&client, 2, topic_filters, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 5);
}

TEST(Client, PublishDupQOS1) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options1 = lwmqtt_default_connect_options;
  options1.client_id = lwmqtt_string("lwmqtt");
  options1.username = lwmqtt_string("public");
  options1.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options1, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS1, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS1;
  msg.payload = payload;
  msg.payload_len = PAYLOAD_LEN;

  // send message with default options1
  lwmqtt_publish_options_t options2 = lwmqtt_default_publish_options;
  err = lwmqtt_publish(&client, &options2, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  // send message and capture id and skip ack
  uint16_t dup_id;
  options2.dup_id = &dup_id;
  options2.skip_ack = true;
  err = lwmqtt_publish(&client, &options2, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);
  ASSERT_TRUE(dup_id > 0);

  // send message again with same id
  err = lwmqtt_publish(&client, &options2, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  /* with QoS1 the broker will send the message again */

  while (counter < 3) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_EQ(counter, 3);
}

TEST(Client, PublishDupQOS2) {
  lwmqtt_posix_network_t network = lwmqtt_default_posix_network;
  lwmqtt_posix_timer_t timer1, timer2;

  lwmqtt_client_t client;

  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  lwmqtt_set_network(&client, &network, lwmqtt_posix_network_read, lwmqtt_posix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_posix_timer_set, lwmqtt_posix_timer_get);
  lwmqtt_set_callback(&client, (void *)custom_ref, message_arrived);

  lwmqtt_err_t err = lwmqtt_posix_network_connect(&network, (char *)"public.cloud.shiftr.io", 1883);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_connect_options_t options = lwmqtt_default_connect_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");

  err = lwmqtt_connect(&client, &options, nullptr, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_subscribe_one(&client, lwmqtt_string("lwmqtt"), LWMQTT_QOS1, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  counter = 0;

  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS2;
  msg.payload = payload;
  msg.payload_len = PAYLOAD_LEN;

  // send message with default options
  lwmqtt_publish_options_t opts = lwmqtt_default_publish_options;
  err = lwmqtt_publish(&client, &opts, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  // send message and capture id and skip ack
  uint16_t dup_id;
  opts.dup_id = &dup_id;
  opts.skip_ack = true;
  err = lwmqtt_publish(&client, &opts, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);
  ASSERT_TRUE(dup_id > 0);

  // send message again with same id
  err = lwmqtt_publish(&client, &opts, lwmqtt_string("lwmqtt"), msg, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  /* with QoS2 the broker may or may not forward the immediate resend, depending on when it completes the skipped
   * handshake on the wire */

  while (counter < 2) {
    size_t available = 0;
    err = lwmqtt_posix_network_peek(&network, &available);
    ASSERT_EQ(err, LWMQTT_SUCCESS);

    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      ASSERT_EQ(err, LWMQTT_SUCCESS);
    }
  }

  err = lwmqtt_unsubscribe_one(&client, lwmqtt_string("lwmqtt"), COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  err = lwmqtt_disconnect(&client, COMMAND_TIMEOUT);
  ASSERT_EQ(err, LWMQTT_SUCCESS);

  lwmqtt_posix_network_disconnect(&network);
  ASSERT_TRUE(counter == 2 || counter == 3);
}

// A scripted network on a fake clock: the first `split` incoming bytes arrive at `first`, the rest at `second` (never
// if negative). Instead of blocking, reads advance the clock to the next arrival or by their timeout.
struct fake_network_t {
  int32_t now;
  uint8_t in[64];
  size_t in_len, in_pos, split;
  int32_t first, second;
  uint32_t last_timeout;
  uint8_t out[64];
  size_t out_len;
};

struct fake_timer_t {
  fake_network_t *network;
  int32_t deadline;
};

struct fake_t {
  fake_network_t network;
  fake_timer_t timer1, timer2;
  uint8_t write_buf[64], read_buf[64];
  lwmqtt_client_t client;
  int messages;
};

static size_t fake_arrived(fake_network_t *n, int32_t time) {
  size_t arrived = 0;
  if (n->first >= 0 && n->first <= time) {
    arrived = n->split;
  }
  if (n->second >= 0 && n->second <= time) {
    arrived = n->in_len;
  }
  return arrived;
}

static lwmqtt_err_t fake_network_read(void *ref, uint8_t *buf, size_t len, size_t *read, uint32_t timeout) {
  auto n = (fake_network_t *)ref;
  *read = 0;
  n->last_timeout = timeout;

  // a zero timeout blocks forever on posix
  EXPECT_GT(timeout, 0u);

  // wait for the next arrival or the timeout
  if (fake_arrived(n, n->now) == n->in_pos) {
    int32_t next = n->in_pos < n->split ? n->first : n->second;
    if (next < 0 || next > n->now + (int32_t)timeout) {
      n->now += (int32_t)timeout;
      return LWMQTT_SUCCESS;
    }
    n->now = next;
  }

  // read arrived data
  size_t count = std::min(len, fake_arrived(n, n->now) - n->in_pos);
  memcpy(buf, n->in + n->in_pos, count);
  n->in_pos += count;
  *read = count;

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t fake_network_write(void *ref, uint8_t *buf, size_t len, size_t *sent, uint32_t timeout) {
  auto n = (fake_network_t *)ref;
  EXPECT_GT(timeout, 0u);
  if (n->out_len + len > sizeof(n->out)) {
    ADD_FAILURE() << "fake network output overflow";
    return LWMQTT_NETWORK_FAILED_WRITE;
  }
  memcpy(n->out + n->out_len, buf, len);
  n->out_len += len;
  *sent = len;
  return LWMQTT_SUCCESS;
}

static void fake_timer_set(void *ref, uint32_t timeout) {
  auto t = (fake_timer_t *)ref;
  t->deadline = t->network->now + (int32_t)timeout;
}

static int32_t fake_timer_get(void *ref) {
  auto t = (fake_timer_t *)ref;
  return t->deadline - t->network->now;
}

static void fake_message_arrived(lwmqtt_client_t *c, void *ref, lwmqtt_string_t t, lwmqtt_message_t m) {
  ((fake_t *)ref)->messages++;
}

static void fake_init(fake_t *f, const std::vector<uint8_t> &in, size_t split, int32_t first, int32_t second) {
  ASSERT_LE(in.size(), sizeof(f->network.in));
  memset(f, 0, sizeof(fake_t));
  memcpy(f->network.in, in.data(), in.size());
  f->network.in_len = in.size();
  f->network.split = split;
  f->network.first = first;
  f->network.second = second;
  f->timer1.network = &f->network;
  f->timer2.network = &f->network;
  lwmqtt_init(&f->client, f->write_buf, sizeof(f->write_buf), f->read_buf, sizeof(f->read_buf));
  lwmqtt_set_network(&f->client, &f->network, fake_network_read, fake_network_write);
  lwmqtt_set_timers(&f->client, &f->timer1, &f->timer2, fake_timer_set, fake_timer_get);
  lwmqtt_set_callback(&f->client, f, fake_message_arrived);
}

TEST(Client, SubscribeFailure) {
  lwmqtt_string_t topics[2] = {lwmqtt_string("a"), lwmqtt_string("b")};
  lwmqtt_qos_t qos[2] = {LWMQTT_QOS1, LWMQTT_QOS1};

  // one subscription failed
  fake_t f;
  fake_init(&f, {0x90, 0x04, 0x00, 0x01, 0x01, 0x80}, 6, 0, -1);
  lwmqtt_err_t err = lwmqtt_subscribe(&f.client, 2, topics, qos, 100);
  ASSERT_EQ(err, LWMQTT_FAILED_SUBSCRIPTION);

  // all subscriptions succeeded
  fake_init(&f, {0x90, 0x04, 0x00, 0x01, 0x01, 0x01}, 6, 0, -1);
  err = lwmqtt_subscribe(&f.client, 2, topics, qos, 100);
  ASSERT_EQ(err, LWMQTT_SUCCESS);
}
