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

 *******************************************************************************/

#include "client.h"
#include "identified.h"
#include "packet.h"
#include "publish.h"
#include "subscribe.h"
#include "unsubscribe.h"

static int lwmqtt_get_next_packet_id(lwmqtt_client_t *c) {
  return c->next_packet_id = (c->next_packet_id == 65535) ? 1 : c->next_packet_id + 1;
}

static int lwmqtt_send_packet(lwmqtt_client_t *c, int length) {
  int rc, sent = 0;

  while (sent < length && c->timer_get(c, c->timer_network_ref) > 0) {
    rc = c->networked_write(c, c->network_ref, &c->write_buf[sent], length, c->timer_get(c, c->timer_network_ref));

    if (rc < 0) {  // there was an error writing the data
      break;
    }

    sent += rc;
  }

  if (sent == length) {
    // reset keep alive timer
    c->timer_set(c, c->timer_keep_alive_ref, c->keep_alive_interval * 1000);

    rc = LWMQTT_SUCCESS;
  } else {
    rc = LWMQTT_FAILURE;
  }

  return rc;
}

void lwmqtt_client_init(lwmqtt_client_t *c, unsigned int command_timeout, unsigned char *write_buf, int write_buf_size,
                        unsigned char *read_buf, int read_buf_size) {
  c->command_timeout = command_timeout;
  c->write_buf = write_buf;
  c->write_buf_size = write_buf_size;
  c->read_buf = read_buf;
  c->read_buf_size = read_buf_size;
  c->is_connected = 0;
  c->ping_outstanding = 0;
  c->callback = NULL;
  c->next_packet_id = 1;
}

void lwmqtt_client_set_network(lwmqtt_client_t *c, void *ref, lwmqtt_network_read_t read,
                               lwmqtt_network_write_t write) {
  c->network_ref = ref;
  c->network_read = read;
  c->networked_write = write;
}

void lwmqtt_client_set_timers(lwmqtt_client_t *c, void *keep_alive_ref, void *network_ref, lwmqtt_timer_set_t set,
                              lwmqtt_timer_get_t get) {
  c->timer_keep_alive_ref = keep_alive_ref;
  c->timer_network_ref = network_ref;
  c->timer_set = set;
  c->timer_get = get;

  c->timer_set(c, c->timer_keep_alive_ref, 0);
  c->timer_set(c, c->timer_network_ref, 0);
}

void lwmqtt_client_set_callback(lwmqtt_client_t *c, lwmqtt_callback_t cb) { c->callback = cb; }

// TODO: Duplicate code...
static int lwmqtt_decode_packet(lwmqtt_client_t *c, int *value, int timeout) {
  unsigned char i;
  int multiplier = 1;
  int len = 0;

  *value = 0;
  do {
    len++;
    if (len > 4) {
      return LWMQTT_HEADER_DECODE_ERROR;  // bad data
    }

    int rc = c->network_read(c, c->network_ref, &i, 1, timeout);
    if (rc != 1) {
      return len;
    }

    *value += (i & 127) * multiplier;
    multiplier *= 128;
  } while ((i & 128) != 0);

  return len;
}

static int lwmqtt_read_packet(lwmqtt_client_t *c) {
  lwmqtt_header_t header = {0};
  int len = 0;
  int rem_len = 0;

  // 1. read the header byte.  This has the src type in it
  int rc = c->network_read(c, c->network_ref, c->read_buf, 1, c->timer_get(c, c->timer_network_ref));
  if (rc != 1) {
    return rc;
  }

  len = 1;

  // 2. read the remaining length.  This is variable in itself
  len += lwmqtt_decode_packet(c, &rem_len, c->timer_get(c, c->timer_network_ref));

  // TODO: Can we remove this unnecessary call?
  lwmqtt_encode_remaining_length(c->read_buf + 1, rem_len);  // put the original remaining length back into the buffer

  // 3. read the rest of the buffer using a callback to supply the rest of the data
  if (rem_len > 0 && (rc = c->network_read(c, c->network_ref, c->read_buf + len, rem_len,
                                           c->timer_get(c, c->timer_network_ref)) != rem_len)) {
    return rc;
  }

  header.byte = c->read_buf[0];

  return header.bits.type;
}

static int lwmqtt_keep_alive(lwmqtt_client_t *c) {
  int rc = LWMQTT_FAILURE;

  if (c->keep_alive_interval == 0) {
    return LWMQTT_SUCCESS;
  }

  // TODO: Retain global network timer and use command timeout to send the message?

  // check if keep alive timer is expired
  if (c->timer_get(c, c->timer_keep_alive_ref) <= 0) {
    if (!c->ping_outstanding) {
      // reset network timer
      // TODO: Should we pass in a timeout from cycle?
      c->timer_set(c, c->timer_network_ref, 1000);

      int len;
      lwmqtt_serialize_pingreq(c->write_buf, c->write_buf_size, &len);
      if (len > 0 && (rc = lwmqtt_send_packet(c, len)) == LWMQTT_SUCCESS) {  // send the ping src
        c->ping_outstanding = 1;
      }
    }
  }

  return rc;
}

// TODO: Send Pubcomp after receiving a Pubrel?

static int lwmqtt_cycle(lwmqtt_client_t *c) {
  // read the socket, see what work is due
  int packet_type = lwmqtt_read_packet(c);
  if (packet_type == 0) {
    return LWMQTT_FAILURE;  // no more data to read, unrecoverable
  }

  int len = 0, rc = LWMQTT_SUCCESS;

  switch (packet_type) {
    case LWMQTT_PUBLISH_PACKET: {
      lwmqtt_string_t topicName;
      lwmqtt_message_t msg;

      int intQoS;

      if (lwmqtt_deserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topicName,
                                     (unsigned char **)&msg.payload, (int *)&msg.payload_len, c->read_buf,
                                     c->read_buf_size) != 1) {
        return LWMQTT_FAILURE;
      }

      msg.qos = (lwmqtt_qos_t)intQoS;

      if (c->callback != NULL) {
        c->callback(c, &topicName, &msg);
      }

      if (msg.qos != LWMQTT_QOS0) {
        if (msg.qos == LWMQTT_QOS1) {
          len = lwmqtt_serialize_puback(c->write_buf, c->write_buf_size, msg.id);
        } else if (msg.qos == LWMQTT_QOS2) {
          len = lwmqtt_serialize_pubrec(c->write_buf, c->write_buf_size, msg.id);
        }

        if (len <= 0) {
          rc = LWMQTT_FAILURE;
        } else {
          rc = lwmqtt_send_packet(c, len);
        }

        if (rc == LWMQTT_FAILURE) {
          return LWMQTT_FAILURE;
        }
      }

      break;
    }
    case LWMQTT_PUBREC_PACKET: {
      unsigned short packet_id;
      unsigned char dup, type;

      if (lwmqtt_deserialize_identified(&type, &dup, &packet_id, c->read_buf, c->read_buf_size) != 1) {
        rc = LWMQTT_FAILURE;
      } else if ((len = lwmqtt_serialize_pubrel(c->write_buf, c->write_buf_size, 0, packet_id)) <= 0) {
        rc = LWMQTT_FAILURE;
      } else if ((rc = lwmqtt_send_packet(c, len)) != LWMQTT_SUCCESS) {
        rc = LWMQTT_FAILURE;
      }

      if (rc == LWMQTT_FAILURE) {
        return LWMQTT_FAILURE;
      }

      break;
    }
    case LWMQTT_PINGRESP_PACKET: {
      c->ping_outstanding = 0;
      break;
    }
    default: { break; }
  }

  lwmqtt_keep_alive(c);

  if (rc == LWMQTT_SUCCESS && packet_type != LWMQTT_FAILURE) {
    rc = packet_type;
  }

  return rc;
}

int rc = LWMQTT_SUCCESS;

int lwmqtt_client_yield(lwmqtt_client_t *c, unsigned int timeout_ms) {
  c->timer_set(c, c->timer_network_ref, timeout_ms);

  do {
    if (lwmqtt_cycle(c) == LWMQTT_FAILURE) {
      rc = LWMQTT_FAILURE;
      break;
    }
  } while (c->timer_get(c, c->timer_network_ref) > 0);

  return rc;
}

static int lwmqtt_cycle_until(lwmqtt_client_t *c, int packet_type) {
  int rc = LWMQTT_FAILURE;

  do {
    if (c->timer_get(c, c->timer_network_ref) <= 0) break;  // we timed out
  } while ((rc = lwmqtt_cycle(c)) != packet_type);

  return rc;
}

int lwmqtt_client_connect(lwmqtt_client_t *c, lwmqtt_options_t *options, lwmqtt_will_t *will,
                          lwmqtt_connack_t *connack) {
  // return immediately if already connected
  if (c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timer to command timeout
  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  // save keep alive interval
  c->keep_alive_interval = options->keep_alive;

  // set keep alive timer
  // TODO: Skip that is keep alive is zero?
  c->timer_set(c, c->timer_keep_alive_ref, c->keep_alive_interval * 1000);

  // serialize connect packet
  int len;
  if (lwmqtt_serialize_connect(c->write_buf, c->write_buf_size, &len, options, will) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // send packet
  if (lwmqtt_send_packet(c, len) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // wait for connack packet
  if (lwmqtt_cycle_until(c, LWMQTT_CONNACK_PACKET) != LWMQTT_CONNACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // deserialize connack packet
  bool session_present;
  lwmqtt_connack_t return_code;
  if (lwmqtt_deserialize_connack(&session_present, &return_code, c->read_buf, c->read_buf_size) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // set return code if pointer is present
  if (connack != NULL) {
    *connack = return_code;
  }

  // return error if connection was not accepted
  if (return_code != LWMQTT_CONNACK_CONNECTION_ACCEPTED) {
    return LWMQTT_FAILURE;
  }

  // set connected flag
  c->is_connected = 1;

  return LWMQTT_SUCCESS;
}

int lwmqtt_client_subscribe(lwmqtt_client_t *c, const char *topic_filter, lwmqtt_qos_t qos) {
  int rc = LWMQTT_FAILURE;
  int len = 0;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char *)topic_filter;

  if (!c->is_connected) {
    return rc;
  }

  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  len = lwmqtt_serialize_subscribe(c->write_buf, c->write_buf_size, 0, lwmqtt_get_next_packet_id(c), 1, &topic,
                                   (int *)&qos);
  if (len <= 0) {
    return rc;
  }

  if ((rc = lwmqtt_send_packet(c, len)) != LWMQTT_SUCCESS) {  // send the subscribe src
    return rc;                                                // there was a problem
  }

  if (lwmqtt_cycle_until(c, LWMQTT_SUBACK_PACKET) == LWMQTT_SUBACK_PACKET)  // wait for suback
  {
    int count = 0, grantedQoS = -1;
    unsigned short packet_id;
    if (lwmqtt_deserialize_suback(&packet_id, 1, &count, &grantedQoS, c->read_buf, c->read_buf_size) == 1) {
      rc = grantedQoS;  // 0, 1, 2 or 0x80
    }

    if (rc != 0x80) {
      rc = 0;
    }
  } else {
    rc = LWMQTT_FAILURE;
  }

  return rc;
}

int lwmqtt_client_unsubscribe(lwmqtt_client_t *c, const char *topic_filter) {
  int rc = LWMQTT_FAILURE;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char *)topic_filter;
  int len = 0;

  if (!c->is_connected) {
    return rc;
  }

  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  if ((len = lwmqtt_serialize_unsubscribe(c->write_buf, c->write_buf_size, 0, lwmqtt_get_next_packet_id(c), 1,
                                          &topic)) <= 0) {
    return rc;
  }
  if ((rc = lwmqtt_send_packet(c, len)) != LWMQTT_SUCCESS) {  // send the subscribe src
    return rc;                                                // there was a problem
  }

  if (lwmqtt_cycle_until(c, LWMQTT_UNSUBACK_PACKET) == LWMQTT_UNSUBACK_PACKET) {
    unsigned short packet_id;  // should be the same as the packet id above
    if (lwmqtt_deserialize_unsuback(&packet_id, c->read_buf, c->read_buf_size) == 1) {
      rc = 0;
    }
  } else {
    rc = LWMQTT_FAILURE;
  }

  return rc;
}

int lwmqtt_client_publish(lwmqtt_client_t *c, const char *topicName, lwmqtt_message_t *message) {
  int rc = LWMQTT_FAILURE;
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char *)topicName;
  int len = 0;

  if (!c->is_connected) {
    return rc;
  }

  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  if (message->qos == LWMQTT_QOS1 || message->qos == LWMQTT_QOS2) {
    message->id = lwmqtt_get_next_packet_id(c);
  }

  len = lwmqtt_serialize_publish(c->write_buf, c->write_buf_size, 0, message->qos, message->retained, message->id,
                                 topic, (unsigned char *)message->payload, message->payload_len);
  if (len <= 0) {
    return rc;
  }

  if ((rc = lwmqtt_send_packet(c, len)) != LWMQTT_SUCCESS) {  // send the subscribe src
    return rc;                                                // there was a problem
  }

  if (message->qos == LWMQTT_QOS1) {
    if (lwmqtt_cycle_until(c, LWMQTT_PUBACK_PACKET) == LWMQTT_PUBACK_PACKET) {
      unsigned short packet_id;
      unsigned char dup, type;
      if (lwmqtt_deserialize_identified(&type, &dup, &packet_id, c->read_buf, c->read_buf_size) != 1)
        rc = LWMQTT_FAILURE;
    } else {
      rc = LWMQTT_FAILURE;
    }
  } else if (message->qos == LWMQTT_QOS2) {
    if (lwmqtt_cycle_until(c, LWMQTT_PUBCOMP_PACKET) == LWMQTT_PUBCOMP_PACKET) {
      unsigned short packet_id;
      unsigned char dup, type;
      if (lwmqtt_deserialize_identified(&type, &dup, &packet_id, c->read_buf, c->read_buf_size) != 1)
        rc = LWMQTT_FAILURE;
    } else {
      rc = LWMQTT_FAILURE;
    }
  }

  return rc;
}

int lwmqtt_client_disconnect(lwmqtt_client_t *c) {
  // set timer
  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  // serialize disconnect packet
  int len = 0;
  if (lwmqtt_serialize_disconnect(c->write_buf, c->write_buf_size, &len) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // set connected flag
  c->is_connected = 0;

  // send disconnected packet
  return lwmqtt_send_packet(c, len);
}
