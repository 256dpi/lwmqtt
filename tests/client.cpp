#include <gtest/gtest.h>

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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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
  lwmqtt_posix_network_t network;
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

  /* with QoS2 the broker will not send the message again */

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
  ASSERT_EQ(counter, 2);
}
