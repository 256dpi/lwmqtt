/*******************************************************************************
 * Copyright (c) 2012, 2016 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *   http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Ian Craggs - initial contribution
 *    Ian Craggs - change delimiter option from char to string
 *    Al Stockdill-Mander - Version using the embedded C client
 *    Ian Craggs - update MQTTClient function names
 *******************************************************************************/

#include <string.h>
#include <stdlib.h>

#include "../src/client.h"
#include "unix.h"

const char * topic = "hello";
const char * payload = "world";

volatile int counter;

static void message_arrived(lwmqtt_client_t *c, lwmqtt_string_t *t, lwmqtt_message_t *m) {
  if(lwmqtt_strcmp(t, (char*)topic) != 0) {
    printf("topic is not 'hello'\n");
    exit(-1);
  }

  if(memcmp(payload, m->payload, m->payloadlen) != 0) {
    printf("payload is not 'world'\n");
    exit(-1);
  }

  counter++;
}

static void test(lwmqtt_qos_t qos) {
  unsigned char buf1[100], buf2[100];

  lwmqtt_unix_network_t n;
  lwmqtt_unix_timer_t t1, t2;

  lwmqtt_client_t c = lwmqtt_default_client;

  lwmqtt_client_init(&c, 1000, buf1, 100, buf2, 100);

  lwmqtt_client_set_network(&c, &n, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_client_set_timers(&c, &t1, &t2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_client_set_callback(&c, message_arrived);

  int rc = lwmqtt_unix_network_connect(&n, "0.0.0.0", 1883);
  if (rc != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect\n");
    exit(-1);
  }

  lwmqtt_connect_data_t data = lwmqtt_default_connect_data;
  data.willFlag = 0;
  data.MQTTVersion = 4;
  data.clientID.cstring = "lwmqtt";
  data.username.cstring = "";
  data.password.cstring = "";
  data.keepAliveInterval = 10;
  data.cleansession = 1;

  rc = lwmqtt_client_connect(&c, &data);
  if (rc != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_client_connect\n");
    exit(-1);
  }

  rc = lwmqtt_client_subscribe(&c, "hello", qos);
  if (rc != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_client_subscribe\n");
    exit(-1);
  }

  counter = 0;

  while (counter < 5) {
    lwmqtt_message_t msg;
    msg.qos = qos;
    msg.payload = "world";
    msg.payloadlen = 5;

    rc = lwmqtt_client_publish(&c, "hello", &msg);
    if (rc != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_client_publish\n");
      exit(-1);
    }

    rc = lwmqtt_client_yield(&c, 10);
    if (rc != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_client_yield\n");
      exit(-1);
    }
  }

  rc = lwmqtt_client_disconnect(&c);
  if (rc != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_client_disconnect\n");
    exit(-1);
  }

  lwmqtt_unix_network_disconnect(&n);
}

int main() {
  printf("Running QoS 0 tests...\n");
  test(LWMQTT_QOS0);

  printf("Running QoS 1 tests...\n");
  test(LWMQTT_QOS1);

  printf("Running QoS 2 tests...\n");
  test(LWMQTT_QOS2);

  printf("Finished all tests.\n");

  return 0;
}
