#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <lwmqtt/unix.h>

#define COMMAND_TIMEOUT 5000
#define MESSAGE_TIMEOUT 1000

lwmqtt_unix_network_t network = {0};

lwmqtt_unix_timer_t timer1, timer2, timer3;

lwmqtt_client_t client;

static void prop_printer(void *ref, lwmqtt_property_t prop) {
  switch (prop.prop) {
      // one byte
    case LWMQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
    case LWMQTT_PROP_REQUEST_PROBLEM_INFORMATION:
    case LWMQTT_PROP_MAXIMUM_QOS:
    case LWMQTT_PROP_RETAIN_AVAILABLE:
    case LWMQTT_PROP_REQUEST_RESPONSE_INFORMATION:
    case LWMQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
    case LWMQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
    case LWMQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
      printf("  Property %x (byte): 0x%x\n", prop.prop, prop.value.byte);
      break;

      // two byte int
    case LWMQTT_PROP_SERVER_KEEP_ALIVE:
    case LWMQTT_PROP_RECEIVE_MAXIMUM:
    case LWMQTT_PROP_TOPIC_ALIAS_MAXIMUM:
    case LWMQTT_PROP_TOPIC_ALIAS:
      printf("  Property %x (int): %d\n", prop.prop, prop.value.int16);
      break;

      // 4 byte int
    case LWMQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
    case LWMQTT_PROP_SESSION_EXPIRY_INTERVAL:
    case LWMQTT_PROP_WILL_DELAY_INTERVAL:
    case LWMQTT_PROP_MAXIMUM_PACKET_SIZE:
      printf("  Property %x (int32): %d\n", prop.prop, prop.value.int32);
      break;

      // Variable byte int
    case LWMQTT_PROP_SUBSCRIPTION_IDENTIFIER:
      printf("  Property %x (varint): %d\n", prop.prop, prop.value.int32);
      break;

      // UTF-8 string
    case LWMQTT_PROP_CONTENT_TYPE:
    case LWMQTT_PROP_RESPONSE_TOPIC:
    case LWMQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
    case LWMQTT_PROP_AUTHENTICATION_METHOD:
    case LWMQTT_PROP_RESPONSE_INFORMATION:
    case LWMQTT_PROP_SERVER_REFERENCE:
    case LWMQTT_PROP_REASON_STRING:

      // Arbitrary blobs as the same encoding.
    case LWMQTT_PROP_CORRELATION_DATA:
    case LWMQTT_PROP_AUTHENTICATION_DATA:
      printf("  Property %x (string): %.*s\n", prop.prop, prop.value.str.len, prop.value.str.data);
      break;

    case LWMQTT_PROP_USER_PROPERTY:
      printf("  User property: k=%.*s, v=%.*s\n", prop.value.pair.k.len, prop.value.pair.k.data, prop.value.pair.v.len,
             prop.value.pair.v.data);
  }
}

static void message_arrived(lwmqtt_client_t *_client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg,
                            lwmqtt_serialized_properties_t props) {
  printf("message_arrived: %.*s => %.*s (%d)\n", (int)topic.len, topic.data, (int)msg.payload_len, (char *)msg.payload,
         (int)msg.payload_len);

  lwmqtt_property_visitor(NULL, props, prop_printer);
}

int main() {
  // initialize client
  lwmqtt_init(&client, malloc(512), 512, malloc(512), 512);

  // configure client
  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, NULL, message_arrived);
  lwmqtt_set_protocol(&client, LWMQTT_MQTT5);

  // configure message time
  lwmqtt_unix_timer_set(&timer3, MESSAGE_TIMEOUT);

  // connect to broker
  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, "localhost", 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect: %d\n", err);
    exit(1);
  }

  // prepare options
  lwmqtt_options_t options = lwmqtt_default_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("public");
  options.password = lwmqtt_string("public");
  options.keep_alive = 5;

  // send connect packet
  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, options, NULL, &return_code, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, return_code);
    exit(1);
  }

  // log
  printf("connected!\n");

  // subscribe to topic
  lwmqtt_sub_options_t subopts = lwmqtt_default_sub_options;
  err = lwmqtt_subscribe_one(&client, lwmqtt_string("hello"), subopts, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_subscribe: %d\n", err);
    exit(1);
  }

  // loop forever
  for (;;) {
    // check if data is available
    size_t available = 0;
    err = lwmqtt_unix_network_peek(&network, &available);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_unix_network_peek: %d\n", err);
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
    if (lwmqtt_unix_timer_get(&timer3) <= 0) {
      // prepare message
      lwmqtt_message_t msg = {.qos = LWMQTT_QOS0, .retained = true, .payload = (uint8_t *)("world"), .payload_len = 5};

      // publish message
      lwmqtt_property_t proplist[] = {
          {.prop = LWMQTT_PROP_MESSAGE_EXPIRY_INTERVAL, .value = {.int32 = 30}},
          {.prop = LWMQTT_PROP_USER_PROPERTY,
           .value = {.pair = {.k = lwmqtt_string("hello from"), .v = lwmqtt_string("lwmqtt")}}},
      };

      lwmqtt_properties_t props = {2, (lwmqtt_property_t *)&proplist};
      err = lwmqtt_publish(&client, lwmqtt_string("hello"), msg, props, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_keep_alive: %d\n", err);
        exit(1);
      }

      // reset timer
      lwmqtt_unix_timer_set(&timer3, MESSAGE_TIMEOUT);
    }

    // sleep for 100ms
    usleep(100 * 1000);
  }
}
