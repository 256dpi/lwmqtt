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
#include "subscribe.h"
#include "unsubscribe.h"

static int lwmqtt_get_next_packet_id(lwmqtt_client_t *c) {
  return c->next_packetid = (c->next_packetid == 65535) ? 1 : c->next_packetid + 1;
}

static int lwmqtt_send_packet(lwmqtt_client_t *c, int length, Timer *timer) {
  int rc = LWMQTT_FAILURE, sent = 0;

  while (sent < length && !TimerIsExpired(timer)) {
    rc = c->ipstack->write(c->ipstack, &c->buf[sent], length, TimerLeftMS(timer));
    if (rc < 0)  // there was an error writing the data
      break;
    sent += rc;
  }
  if (sent == length) {
    TimerCountdown(&c->ping_timer, c->keepAliveInterval);  // record the fact that we have successfully sent the src
    rc = LWMQTT_SUCCESS;
  } else
    rc = LWMQTT_FAILURE;
  return rc;
}

void lwmqtt_client_init(lwmqtt_client_t *c, Network *network, unsigned int command_timeout_ms, unsigned char *sendbuf,
                        size_t sendbuf_size, unsigned char *readbuf, size_t readbuf_size) {
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

static int lwmqtt_decode_packet(lwmqtt_client_t *c, int *value, int timeout) {
  unsigned char i;
  int multiplier = 1;
  int len = 0;
  const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

  *value = 0;
  do {
    int rc = MQTTPACKET_READ_ERROR;

    if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
      // TODO: rc and len seem to be mixed up here.
      rc = MQTTPACKET_READ_ERROR; /* bad data */
      return len;
    }
    rc = c->ipstack->read(c->ipstack, &i, 1, timeout);
    if (rc != 1) return len;
    *value += (i & 127) * multiplier;
    multiplier *= 128;
  } while ((i & 128) != 0);

  return len;
}

static int lwmqtt_read_packet(lwmqtt_client_t *c, Timer *timer) {
  lwmqtt_header_t header = {0};
  int len = 0;
  int rem_len = 0;

  /* 1. read the header byte.  This has the src type in it */
  int rc = c->ipstack->read(c->ipstack, c->readbuf, 1, TimerLeftMS(timer));
  if (rc != 1) return rc;

  len = 1;
  /* 2. read the remaining length.  This is variable in itself */
  lwmqtt_decode_packet(c, &rem_len, TimerLeftMS(timer));
  len += lwmqtt_packet_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */

  /* 3. read the rest of the buffer using a callback to supply the rest of the data */
  if (rem_len > 0 && (rc = c->ipstack->read(c->ipstack, c->readbuf + len, rem_len, TimerLeftMS(timer)) != rem_len))
    return rc;

  header.byte = c->readbuf[0];

  return header.bits.type;
}

static int lwmqtt_keep_alive(lwmqtt_client_t *c) {
  int rc = LWMQTT_FAILURE;

  if (c->keepAliveInterval == 0) {
    return LWMQTT_SUCCESS;
  }

  if (TimerIsExpired(&c->ping_timer)) {
    if (!c->ping_outstanding) {
      Timer timer;
      TimerInit(&timer);
      TimerCountdownMS(&timer, 1000);
      int len = lwmqtt_serialize_pingreq(c->buf, c->buf_size);
      if (len > 0 && (rc = lwmqtt_send_packet(c, len, &timer)) == LWMQTT_SUCCESS)  // send the ping src
        c->ping_outstanding = 1;
    }
  }

  return rc;
}

static int lwmqtt_cycle(lwmqtt_client_t *c, Timer *timer) {
  // read the socket, see what work is due
  int packet_type = lwmqtt_read_packet(c, timer);
  if (packet_type == 0) return LWMQTT_FAILURE;  // no more data to read, unrecoverable

  int len = 0, rc = LWMQTT_SUCCESS;

  switch (packet_type) {
    case CONNACK:
    case PUBACK:
    case SUBACK:
      break;
    case PUBLISH: {
      lwmqtt_string_t topicName;
      lwmqtt_message_t msg;
      int intQoS;
      if (lwmqtt_deserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
                                     (unsigned char **)&msg.payload, (int *)&msg.payloadlen, c->readbuf,
                                     c->readbuf_size) != 1)
        goto exit;
      msg.qos = (lwmqtt_qos_t)intQoS;

      if (c->callback != NULL) {
        c->callback(c, &topicName, &msg);
      }

      if (msg.qos != LWMQTT_QOS0) {
        if (msg.qos == LWMQTT_QOS1)
          len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
        else if (msg.qos == LWMQTT_QOS2)
          len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
        if (len <= 0)
          rc = LWMQTT_FAILURE;
        else
          rc = lwmqtt_send_packet(c, len, timer);
        if (rc == LWMQTT_FAILURE) goto exit;  // there was a problem
      }
      break;
    }
    case PUBREC: {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
        rc = LWMQTT_FAILURE;
      else if ((len = lwmqtt_serialize_ack(c->buf, c->buf_size, PUBREL, 0, mypacketid)) <= 0)
        rc = LWMQTT_FAILURE;
      else if ((rc = lwmqtt_send_packet(c, len, timer)) != LWMQTT_SUCCESS)  // send the PUBREL src
        rc = LWMQTT_FAILURE;                                                // there was a problem
      if (rc == LWMQTT_FAILURE) goto exit;                                  // there was a problem
      break;
    }
    case PUBCOMP:
      break;
    case PINGRESP:
      c->ping_outstanding = 0;
      break;
  }
  lwmqtt_keep_alive(c);

// TODO: Remove goto and label.
exit:
  if (rc == LWMQTT_SUCCESS && packet_type != LWMQTT_FAILURE) rc = packet_type;
  return rc;
}

int lwmqtt_client_yield(lwmqtt_client_t *c, int timeout_ms) {
  int rc = LWMQTT_SUCCESS;
  Timer timer;

  TimerInit(&timer);
  TimerCountdownMS(&timer, timeout_ms);

  do {
    if (lwmqtt_cycle(c, &timer) == LWMQTT_FAILURE) {
      rc = LWMQTT_FAILURE;
      break;
    }
  } while (!TimerIsExpired(&timer));

  return rc;
}

static int lwmqtt_cycle_until(lwmqtt_client_t *c, int packet_type, Timer *timer) {
  int rc = LWMQTT_FAILURE;

  do {
    if (TimerIsExpired(timer)) break;  // we timed out
  } while ((rc = lwmqtt_cycle(c, timer)) != packet_type);

  return rc;
}

int lwmqtt_client_connect(lwmqtt_client_t *c, lwmqtt_connect_data_t *options) {
  Timer connect_timer;
  int rc = LWMQTT_FAILURE;
  lwmqtt_connect_data_t default_options = lwmqtt_default_connect_data;
  int len = 0;

  if (c->isconnected) /* don't send connect src again if we are already connected */
    goto exit;

  TimerInit(&connect_timer);
  TimerCountdownMS(&connect_timer, c->command_timeout_ms);

  if (options == 0) options = &default_options; /* set default options if none were supplied */

  c->keepAliveInterval = options->keepAliveInterval;
  TimerCountdown(&c->ping_timer, c->keepAliveInterval);
  if ((len = lwmqtt_serialize_connect(c->buf, c->buf_size, options)) <= 0) goto exit;
  if ((rc = lwmqtt_send_packet(c, len, &connect_timer)) != LWMQTT_SUCCESS)  // send the connect src
    goto exit;                                                              // there was a problem

  // this will be a blocking call, wait for the connack
  if (lwmqtt_cycle_until(c, CONNACK, &connect_timer) == CONNACK) {
    unsigned char connack_rc = 255;
    unsigned char sessionPresent = 0;
    if (lwmqtt_deserialize_connack(&sessionPresent, &connack_rc, c->readbuf, c->readbuf_size) == 1)
      rc = connack_rc;
    else
      rc = LWMQTT_FAILURE;
  } else
    rc = LWMQTT_FAILURE;

// TODO: Remove goto and label.
exit:
  if (rc == LWMQTT_SUCCESS) c->isconnected = 1;

  return rc;
}

int lwmqtt_client_subscribe(lwmqtt_client_t *c, const char *topicFilter, lwmqtt_qos_t qos) {
  int rc = LWMQTT_FAILURE;
  Timer timer;
  int len = 0;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.cstring = (char *)topicFilter;

  if (!c->isconnected) return rc;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  len = lwmqtt_serialize_subscribe(c->buf, c->buf_size, 0, lwmqtt_get_next_packet_id(c), 1, &topic, (int *)&qos);
  if (len <= 0) return rc;
  if ((rc = lwmqtt_send_packet(c, len, &timer)) != LWMQTT_SUCCESS)  // send the subscribe src
    return rc;                                                      // there was a problem

  if (lwmqtt_cycle_until(c, SUBACK, &timer) == SUBACK)  // wait for suback
  {
    int count = 0, grantedQoS = -1;
    unsigned short mypacketid;
    if (lwmqtt_deserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
      rc = grantedQoS;  // 0, 1, 2 or 0x80
    if (rc != 0x80) {
      rc = 0;
    }
  } else
    rc = LWMQTT_FAILURE;

  return rc;
}

int lwmqtt_client_unsubscribe(lwmqtt_client_t *c, const char *topicFilter) {
  int rc = LWMQTT_FAILURE;
  Timer timer;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.cstring = (char *)topicFilter;
  int len = 0;

  if (!c->isconnected) return rc;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  if ((len = lwmqtt_serialize_unsubscribe(c->buf, c->buf_size, 0, lwmqtt_get_next_packet_id(c), 1, &topic)) <= 0)
    return rc;
  if ((rc = lwmqtt_send_packet(c, len, &timer)) != LWMQTT_SUCCESS)  // send the subscribe src
    return rc;                                                      // there was a problem

  if (lwmqtt_cycle_until(c, UNSUBACK, &timer) == UNSUBACK) {
    unsigned short mypacketid;  // should be the same as the packetid above
    if (lwmqtt_deserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1) rc = 0;
  } else
    rc = LWMQTT_FAILURE;

  return rc;
}

int lwmqtt_client_publish(lwmqtt_client_t *c, const char *topicName, lwmqtt_message_t *message) {
  int rc = LWMQTT_FAILURE;
  Timer timer;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.cstring = (char *)topicName;
  int len = 0;

  if (!c->isconnected) return rc;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  if (message->qos == LWMQTT_QOS1 || message->qos == LWMQTT_QOS2) message->id = lwmqtt_get_next_packet_id(c);

  len = lwmqtt_serialize_publish(c->buf, c->buf_size, 0, message->qos, message->retained, message->id, topic,
                                 (unsigned char *)message->payload, message->payloadlen);
  if (len <= 0) return rc;
  if ((rc = lwmqtt_send_packet(c, len, &timer)) != LWMQTT_SUCCESS)  // send the subscribe src
    return rc;                                                      // there was a problem

  if (message->qos == LWMQTT_QOS1) {
    if (lwmqtt_cycle_until(c, PUBACK, &timer) == PUBACK) {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) rc = LWMQTT_FAILURE;
    } else
      rc = LWMQTT_FAILURE;
  } else if (message->qos == LWMQTT_QOS2) {
    if (lwmqtt_cycle_until(c, PUBCOMP, &timer) == PUBCOMP) {
      unsigned short mypacketid;
      unsigned char dup, type;
      if (lwmqtt_deserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1) rc = LWMQTT_FAILURE;
    } else
      rc = LWMQTT_FAILURE;
  }

  return rc;
}

int lwmqtt_client_disconnect(lwmqtt_client_t *c) {
  int rc = LWMQTT_FAILURE;
  Timer timer;  // we might wait for incomplete incoming publishes to complete
  int len = 0;

  TimerInit(&timer);
  TimerCountdownMS(&timer, c->command_timeout_ms);

  len = lwmqtt_serialize_disconnect(c->buf, c->buf_size);
  if (len > 0) rc = lwmqtt_send_packet(c, len, &timer);  // send the disconnect src

  c->isconnected = 0;

  return rc;
}
