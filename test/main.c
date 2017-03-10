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

#include "unix.h"
#include "../src/client.h"

volatile int toStop = 0;

void cfinish(int sig) {
  signal(SIGINT, NULL);
  toStop = 1;
}

void messageArrived(lwmqtt_client_t *c, lwmqtt_string_t* topic, lwmqtt_message_t *msg) {
  printf("%.*s\t", topic->lenstring.len, topic->lenstring.data);
  printf("%.*s\n", (int)msg->payloadlen, (char*)msg->payload);
}

int main() {
  int rc = 0;
  unsigned char buf[100];
  unsigned char readbuf[100];

  lwmqtt_unix_network_t n;
  lwmqtt_client_t c = lwmqtt_default_client;

  signal(SIGINT, cfinish);
  signal(SIGTERM, cfinish);

  lwmqtt_unix_network_init(&n);
  lwmqtt_unix_network_connect(&n, "broker.shiftr.io", 1883);
  lwmqtt_client_init(&c, 1000, buf, 100, readbuf, 100);
  lwmqtt_client_set_network(&c, &n, lwmqtt_unix_network_read, lwmqtt_unix_network_write);

  lwmqtt_connect_data_t data = lwmqtt_default_connect_data;
  data.willFlag = 0;
  data.MQTTVersion = 3;
  data.clientID.cstring = "lwmqtt";
  data.username.cstring = "try";
  data.password.cstring = "try";
  data.keepAliveInterval = 10;
  data.cleansession = 1;

  printf("Connecting to %s %d\n", "broker.shiftr.io", 1883);

  rc = lwmqtt_client_connect(&c, &data);
  printf("Connected %d\n", rc);

  printf("Subscribing to hello\n");
  rc = lwmqtt_client_subscribe(&c, "hello", 0);
  printf("Subscribed %d\n", rc);

  while (!toStop) {
    lwmqtt_client_yield(&c, 1000);
  }

  printf("Stopping\n");

  lwmqtt_client_disconnect(&c);
  lwmqtt_unix_network_disconnect(&n);

  return 0;
}
