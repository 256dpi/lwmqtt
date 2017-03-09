/*******************************************************************************
 * Copyright (c) 2014, 2015 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander/Ian Craggs - initial API and implementation and/or initial documentation
 *******************************************************************************/

#include "client.h"
#include "packet.h"
#include "publish.h"
#include "unsubscribe.h"
#include "subscribe.h"

static int getNextPacketId(MQTTClient* c) {
  return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}

static int sendPacket(MQTTClient* c, int length, Timer* timer) {
  int rc = FAILURE, sent = 0;

  while (sent < length && !TimerIsExpired(timer)) {
    rc = c->ipstack->mqttwrite(c->ipstack, &c->buf[sent], length, TimerLeftMS(timer));
    if (rc < 0)  // there was an error writing the data
      break;
    sent += rc;
  }
  if (sent == length) {
    TimerCountdown(&c->ping_timer, c->keepAliveInterval);  // record the fact that we have successfully sent the src
    rc = SUCCESS;
  } else
    rc = FAILURE;
  return rc;
}

void MQTTClientInit(MQTTClient* c, Network* network, unsigned int command_timeout_ms, unsigned char* sendbuf,
                    size_t sendbuf_size, unsigned char* readbuf, size_t readbuf_size) {
  int i;
  c->ipstack = network;

  c->command_timeout_ms = command_timeout_ms;
  c->buf = sendbuf;
  c->buf_size = sendbuf_size;
  c->readbuf = readbuf;
  c->readbuf_size = readbuf_size;
  c->isconnected = 0;
  c->ping_outstanding = 0;
  c->callback = NULL;
  c->next_packetid = 1;
  TimerInit(&c->ping_timer);
}

static int decodePacket(MQTTClient* c, int* value, int timeout) {
  unsigned char i;
  int multiplier = 1;
  int len = 0;
  const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

  *value = 0;
  do {
    int rc = MQTTPACKET_READ_ERROR;

    if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
      rc = MQTTPACKET_READ_ERROR; /* bad data */
      goto exit;
    }
    rc = c->ipstack->mqttread(c->ipstack, &i, 1, timeout);
    if (rc != 1) goto exit;
    *value += (i & 127) * multiplier;
    multiplier *= 128;
  } while ((i & 128) != 0);
exit:
  return len;
}

static int readPacket(MQTTClient* c, Timer* timer) {
  lwmqtt_header_t header = {0};
  int len = 0;
  int rem_len = 0;

  /* 1. read the header byte.  This has the src type in it */
  int rc = c->ipstack->mqttread(c->ipstack, c->readbuf, 1, TimerLeftMS(timer));
  if (rc != 1) goto exit;

  len = 1;
  /* 2. read the remaining length.  This is variable in itself */
  decodePacket(c, &rem_len, TimerLeftMS(timer));
  len += lwmqtt_packet_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

  /* 3. read the rest of the buffer using a callback to supply the rest of the data */
  if (rem_len > 0 && (rc = c->ipstack->mqttread(c->ipstack, c->readbuf + len, rem_len, TimerLeftMS(timer)) != rem_len))
    goto exit;

  header.byte = c->readbuf[0];
  rc = header.bits.type;
exit:
  return rc;
}

int deliverMessage(MQTTClient* c, lwmqtt_string_t* topicName, MQTTMessage* message) {
  int rc = FAILURE;

  if (c->callback != NULL) {
    c->callback(topicName, message);
    rc = SUCCESS;
  }

  return rc;
}

int keepalive(MQTTClient* c) {
  int rc = FAILURE;

  if (c->keepAliveInterval == 0) {
    rc = SUCCESS;
    goto exit;
  }

  if (TimerIsExpired(&c->ping_timer)) {
    if (!c->ping_outstanding) {
      Timer timer;
      TimerInit(&timer);
      TimerCountdownMS(&timer, 1000);
      int len = lwmqtt_serialize_pingreq(c->buf, c->buf_size);
      if (len > 0 && (rc = sendPacket(c, len, &timer)) == SUCCESS)  // send the ping src
        c->ping_outstanding = 1;
    }
  }

exit:
  return rc;
}

int cycle(MQTTClient* c, Timer* timer) {
  // read the socket, see what work is due
  unsigned short packet_type = readPacket(c, timer);
  if (packet_type == 0) return FAILURE;  // no more data to read, unrecoverable

  int len = 0, rc = SUCCESS;

  switch (packet_type) {
    case CONNACK:
    case PUBACK:
    case SUBACK:
      break;
    case PUBLISH: {
      lwmqtt_string_t topicName;
      MQTTMessage msg;
      int intQoS;
      if (lwmqtt_deserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
                                     (unsigned char**)&msg.payload, (int*)&msg.payloadlen, c->readbuf,
                                     c->readbuf_size) != 1)
        goto exit;
      msg.qos = (enum QoS)intQoS;
      deliverMessage(c, &topicName, &msg);
      if (msg.qos != QOS0) {
        if (msg.qos == QOS1)
          len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
        else if (msg.qos == QOS2)
          len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
        if (len <= 0)
          rc = FAILURE;
        else
          rc = sendPacket(c, len, timer);
        if (rc == FAILURE) goto exit;  // there was a problem
      }
      break;
    }
    case PUBREC: {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
        rc = FAILURE;
      else if ((len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBREL, 0, mypacketid)) <= 0)
        rc = FAILURE;
      else if ((rc = sendPacket(c, len, timer)) != SUCCESS)  // send the PUBREL src
        rc = FAILURE;                                        // there was a problem
      if (rc == FAILURE) goto exit;                          // there was a problem
      break;
    }
    case PUBCOMP:
      break;
    case PINGRESP:
      c->ping_outstanding = 0;
      break;
  }
  keepalive(c);
exit:
  if (rc == SUCCESS && packet_type != FAILURE) rc = packet_type;
  return rc;
}

int MQTTYield(MQTTClient* c, int timeout_ms) {
  int rc = SUCCESS;
  Timer timer;

  TimerInit(&timer);
  TimerCountdownMS(&timer, timeout_ms);

  do {
    if (cycle(c, &timer) == FAILURE) {
      rc = FAILURE;
      break;
    }
  } while (!TimerIsExpired(&timer));

  return rc;
}

void MQTTRun(void* parm) {
  Timer timer;
  MQTTClient* c = (MQTTClient*)parm;

  TimerInit(&timer);

  while (1) {
    TimerCountdownMS(&timer, 500); /* Don't wait too long if no traffic is incoming */
    cycle(c, &timer);
  }
}

int waitfor(MQTTClient* c, int packet_type, Timer* timer) {
  int rc = FAILURE;

  do {
    if (TimerIsExpired(timer)) break;  // we timed out
  } while ((rc = cycle(c, timer)) != packet_type);

  return rc;
}

int MQTTConnect(MQTTClient* c, lwmqtt_connect_data* options) {
  Timer connect_timer;
  int rc = FAILURE;
  lwmqtt_connect_data default_options = lwmqtt_default_connect_data;
  int len = 0;

  if (c->isconnected) /* don't send connect src again if we are already connected */
    goto exit;

  TimerInit(&connect_timer);
  TimerCountdownMS(&connect_timer, c->command_timeout_ms);

  if (options == 0) options = &default_options; /* set default options if none were supplied */

  c->keepAliveInterval = options->keepAliveInterval;
  TimerCountdown(&c->ping_timer, c->keepAliveInterval);
  if ((len = lwmqtt_serialize_connect(c->buf, c->buf_size, options)) <= 0) goto exit;
  if ((rc = sendPacket(c, len, &connect_timer)) != SUCCESS)  // send the connect src
    goto exit;                                               // there was a problem

  // this will be a blocking call, wait for the connack
  if (waitfor(c, CONNACK, &connect_timer) == CONNACK) {
    unsigned char connack_rc = 255;
    unsigned char sessionPresent = 0;
    if (lwmqtt_deserialize_connack(&sessionPresent, &connack_rc, c->readbuf, c->readbuf_size) == 1)
      rc = connack_rc;
    else
      rc = FAILURE;
  } else
    rc = FAILURE;

exit:
  if (rc == SUCCESS) c->isconnected = 1;

  return rc;
}

int MQTTSubscribe(MQTTClient* c, const char* topicFilter, enum QoS qos) {
  int rc = FAILURE;
  Timer timer;
  int len = 0;
  lwmqtt_string_t topic = MQTTString_initializer;
  topic.cstring = (char*)topicFilter;

  if (!c->isconnected) goto exit;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  len = lwmqtt_serialize_subscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic, (int*)&qos);
  if (len <= 0) goto exit;
  if ((rc = sendPacket(c, len, &timer)) != SUCCESS)  // send the subscribe src
    goto exit;                                       // there was a problem

  if (waitfor(c, SUBACK, &timer) == SUBACK)  // wait for suback
  {
    int count = 0, grantedQoS = -1;
    unsigned short mypacketid;
    if (lwmqtt_deserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
      rc = grantedQoS;  // 0, 1, 2 or 0x80
    if (rc != 0x80) {
      rc = 0;
    }
  } else
    rc = FAILURE;

exit:
  return rc;
}

int MQTTUnsubscribe(MQTTClient* c, const char* topicFilter) {
  int rc = FAILURE;
  Timer timer;
  lwmqtt_string_t topic = MQTTString_initializer;
  topic.cstring = (char*)topicFilter;
  int len = 0;

  if (!c->isconnected) goto exit;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  if ((len = lwmqtt_serialize_unsubscribe(c->buf, c->buf_size, 0, getNextPacketId(c), 1, &topic)) <= 0) goto exit;
  if ((rc = sendPacket(c, len, &timer)) != SUCCESS)  // send the subscribe src
    goto exit;                                       // there was a problem

  if (waitfor(c, UNSUBACK, &timer) == UNSUBACK) {
    unsigned short mypacketid;  // should be the same as the packetid above
    if (lwmqtt_deserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1) rc = 0;
  } else
    rc = FAILURE;

exit:
  return rc;
}

int MQTTPublish(MQTTClient* c, const char* topicName, MQTTMessage* message) {
  int rc = FAILURE;
  Timer timer;
  lwmqtt_string_t topic = MQTTString_initializer;
  topic.cstring = (char*)topicName;
  int len = 0;

  if (!c->isconnected) goto exit;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  if (message->qos == QOS1 || message->qos == QOS2) message->id = getNextPacketId(c);

  len = lwmqtt_serialize_publish(c->buf, c->buf_size, 0, message->qos, message->retained, message->id, topic,
                                 (unsigned char*)message->payload, message->payloadlen);
  if (len <= 0) goto exit;
  if ((rc = sendPacket(c, len, &timer)) != SUCCESS)  // send the subscribe src
    goto exit;                                       // there was a problem

  if (message->qos == QOS1) {
    if (waitfor(c, PUBACK, &timer) == PUBACK) {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) rc = FAILURE;
    } else
      rc = FAILURE;
  } else if (message->qos == QOS2) {
    if (waitfor(c, PUBCOMP, &timer) == PUBCOMP) {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) rc = FAILURE;
    } else
      rc = FAILURE;
  }

exit:
  return rc;
}

int MQTTDisconnect(MQTTClient* c) {
  int rc = FAILURE;
  Timer timer;  // we might wait for incomplete incoming publishes to complete
  int len = 0;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  len = lwmqtt_serialize_disconnect(c->buf, c->buf_size);
  if (len > 0) rc = sendPacket(c, len, &timer);  // send the disconnect src

  c->isconnected = 0;

  return rc;
}
