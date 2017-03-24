#include <string.h>

#include "client.h"

// TODO: Cleanup code.

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

static unsigned short lwmqtt_get_next_packet_id(lwmqtt_client_t *c) {
  return c->next_packet_id = (unsigned short)((c->next_packet_id == 65535) ? 1 : c->next_packet_id + 1);
}

static lwmqtt_err_t lwmqtt_read_packet(lwmqtt_client_t *c, lwmqtt_packet_t *packet) {
  // prepare read counter
  int read = 0;

  // TODO: Improve method to allow timeouts happening while reading the rest of the packet.

  // read header byte
  lwmqtt_err_t err = c->network_read(c, c->network_ref, c->read_buf, 1, &read, c->timer_get(c, c->timer_network_ref));
  if (err != LWMQTT_SUCCESS) {
    return err;
  } else if (read != 1) {
    return LWMQTT_NO_DATA;
  }

  // detect packet type
  *packet = lwmqtt_detect_packet_type(c->read_buf);
  if (*packet == LWMQTT_INVALID_PACKET) {
    return LWMQTT_FAILURE;
  }

  // prepare variables
  int len = 0;
  int rem_len = 0;

  do {
    // adjust len
    len++;

    // read next byte
    read = 0;
    err = c->network_read(c, c->network_ref, c->read_buf + len, 1, &read, c->timer_get(c, c->timer_network_ref));
    if (err != LWMQTT_SUCCESS) {
      return err;
    } else if (read != 1) {
      return LWMQTT_NOT_ENOUGH_DATA;
    }

    // attempt to detect remaining length
    err = lwmqtt_detect_remaining_length(c->read_buf + 1, len, &rem_len);
  } while (err == LWMQTT_BUFFER_TOO_SHORT);

  // check final error
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // read the rest of the buffer if needed
  if (rem_len > 0) {
    read = 0;
    err = c->network_read(c, c->network_ref, c->read_buf + 1 + len, rem_len, &read,
                          c->timer_get(c, c->timer_network_ref));
    if (err != LWMQTT_SUCCESS) {
      return err;
    } else if (read != rem_len) {
      return LWMQTT_NOT_ENOUGH_DATA;
    }
  }

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t lwmqtt_send_packet(lwmqtt_client_t *c, int length) {
  // prepare counter
  int sent = 0;

  // write until all data is sent or an error is returned
  while (sent < length && c->timer_get(c, c->timer_network_ref) > 0) {
    // write to network
    lwmqtt_err_t err = c->networked_write(c, c->network_ref, &c->write_buf[sent], length, &sent,
                                          c->timer_get(c, c->timer_network_ref));
    if (err != LWMQTT_SUCCESS) {
      return err;
    }
  }

  // check length
  if (sent != length) {
    return LWMQTT_NOT_ENOUGH_DATA;
  }

  // reset keep alive timer
  c->timer_set(c, c->timer_keep_alive_ref, c->keep_alive_interval * 1000);

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t lwmqtt_keep_alive(lwmqtt_client_t *c) {
  // return immediately if keep alive interval is zero
  if (c->keep_alive_interval == 0) {
    return LWMQTT_SUCCESS;
  }

  // fail immediately if a ping is still outstanding
  if (c->ping_outstanding) {
    return LWMQTT_FAILURE;
  }

  // return immediately if no ping is due
  if (c->timer_get(c, c->timer_keep_alive_ref) > 0) {
    return LWMQTT_SUCCESS;
  }

  // TODO: Retain global network timer and use command timeout to send the message?

  // reset network timer
  // TODO: Should we pass in a timeout from cycle?
  c->timer_set(c, c->timer_network_ref, 1000);

  // encode pingreq packet
  int len;
  lwmqtt_err_t err = lwmqtt_encode_zero(c->write_buf, c->write_buf_size, &len, LWMQTT_PINGREQ_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // send packet
  err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // set flag
  c->ping_outstanding = 1;

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t lwmqtt_cycle(lwmqtt_client_t *c, lwmqtt_packet_t *packet) {
  // read next packet from the network
  lwmqtt_err_t err = lwmqtt_read_packet(c, packet);
  if (err == LWMQTT_NO_DATA) {
    return LWMQTT_SUCCESS;
  } else if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // TODO: Send Pubcomp after receiving a Pubrel?

  int len = 0;

  switch (*packet) {
    case LWMQTT_PUBLISH_PACKET: {
      lwmqtt_string_t topicName;
      lwmqtt_message_t msg;

      if (lwmqtt_decode_publish(&msg.dup, &msg.qos, &msg.retained, &msg.id, &topicName, (unsigned char **)&msg.payload,
                                &msg.payload_len, c->read_buf, c->read_buf_size) != LWMQTT_SUCCESS) {
        return LWMQTT_FAILURE;
      }

      if (c->callback != NULL) {
        c->callback(c, &topicName, &msg);
      }

      if (msg.qos != LWMQTT_QOS0) {
        if (msg.qos == LWMQTT_QOS1) {
          lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, LWMQTT_PUBACK_PACKET, false, msg.id);
        } else if (msg.qos == LWMQTT_QOS2) {
          lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, LWMQTT_PUBREC_PACKET, false, msg.id);
        }

        if (len <= 0) {
          return LWMQTT_FAILURE;
        } else {
          // send packet
          err = lwmqtt_send_packet(c, len);
          if (err != LWMQTT_SUCCESS) {
            return err;
          }
        }
      }

      break;
    }

    case LWMQTT_PUBREC_PACKET: {
      unsigned short packet_id;
      lwmqtt_packet_t packet;
      bool dup;

      if (lwmqtt_decode_ack(&packet, &dup, &packet_id, c->read_buf, c->read_buf_size) != LWMQTT_SUCCESS) {
        return LWMQTT_FAILURE;
      } else if (lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, LWMQTT_PUBREL_PACKET, 0, packet_id) <= 0) {
        return LWMQTT_FAILURE;
      } else {
        // send packet
        err = lwmqtt_send_packet(c, len);
        if (err != LWMQTT_SUCCESS) {
          return err;
        }
      }

      break;
    }

    case LWMQTT_PINGRESP_PACKET: {
      c->ping_outstanding = 0;
      break;
    }

    default: { break; }
  }

  // check keep alive
  err = lwmqtt_keep_alive(c);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t lwmqtt_cycle_until(lwmqtt_client_t *c, lwmqtt_packet_t *packet, lwmqtt_packet_t needle) {
  // loop until timeout has been reached
  do {
    // do one cycle
    lwmqtt_err_t err = lwmqtt_cycle(c, packet);
    if (err != LWMQTT_SUCCESS) {
      return err;
    }

    // check if needle has been found
    if (needle != LWMQTT_NO_PACKET && *packet == needle) {
      return LWMQTT_SUCCESS;
    }
  } while (c->timer_get(c, c->timer_network_ref) > 0);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_client_yield(lwmqtt_client_t *c, unsigned int timeout) {
  // set timeout
  c->timer_set(c, c->timer_network_ref, timeout);

  // cycle until timeout has been reached
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  lwmqtt_err_t err = lwmqtt_cycle_until(c, &packet, LWMQTT_NO_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // set timeout
  c->timer_set(c, c->timer_network_ref, timeout);

  return LWMQTT_SUCCESS;
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
  // TODO: Skip that if keep alive is zero?
  c->timer_set(c, c->timer_keep_alive_ref, c->keep_alive_interval * 1000);

  // encode connect packet
  int len;
  if (lwmqtt_encode_connect(c->write_buf, c->write_buf_size, &len, options, will) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // send packet
  lwmqtt_err_t err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // wait for connack packet
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  err = lwmqtt_cycle_until(c, &packet, LWMQTT_CONNACK_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  } else if (packet != LWMQTT_CONNACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // decode connack packet
  bool session_present;
  lwmqtt_connack_t return_code;
  if (lwmqtt_decode_connack(&session_present, &return_code, c->read_buf, c->read_buf_size) != LWMQTT_SUCCESS) {
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

lwmqtt_err_t lwmqtt_client_subscribe(lwmqtt_client_t *c, const char *topic_filter, lwmqtt_qos_t qos) {
  // immediately return error if not connected
  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timeout
  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  // prepare string
  lwmqtt_string_t str = lwmqtt_default_string;
  str.c_string = (char *)topic_filter;

  // encode subscribe packet
  int len;
  lwmqtt_err_t err =
      lwmqtt_encode_subscribe(c->write_buf, c->write_buf_size, &len, lwmqtt_get_next_packet_id(c), 1, &str, &qos);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // send packet
  err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // wait for suback packet
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  err = lwmqtt_cycle_until(c, &packet, LWMQTT_SUBACK_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  } else if (packet != LWMQTT_SUBACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // decode packet
  int count = 0;
  lwmqtt_qos_t grantedQoS;
  unsigned short packet_id;
  err = lwmqtt_decode_suback(&packet_id, 1, &count, &grantedQoS, c->read_buf, c->read_buf_size);
  if (err == LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_client_unsubscribe(lwmqtt_client_t *c, const char *topic_filter) {
  // immediately return error if not connected
  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timer
  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  // prepare string
  lwmqtt_string_t str = lwmqtt_default_string;
  str.c_string = (char *)topic_filter;

  // encode unsubscribe packet
  int len;
  lwmqtt_err_t err =
      lwmqtt_encode_unsubscribe(c->write_buf, c->write_buf_size, &len, lwmqtt_get_next_packet_id(c), 1, &str);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // send unsubscribe packet
  err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // wait for unsuback packet
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  err = lwmqtt_cycle_until(c, &packet, LWMQTT_UNSUBACK_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  } else if (packet != LWMQTT_UNSUBACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // decode unsuback packet
  bool dup;
  unsigned short packet_id;
  err = lwmqtt_decode_ack(&packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}

int lwmqtt_client_publish(lwmqtt_client_t *c, const char *topicName, lwmqtt_message_t *message) {
  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char *)topicName;
  int len = 0;

  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  if (message->qos == LWMQTT_QOS1 || message->qos == LWMQTT_QOS2) {
    message->id = lwmqtt_get_next_packet_id(c);
  }

  int err =
      lwmqtt_encode_publish(c->write_buf, c->write_buf_size, &len, 0, message->qos, (char)(message->retained ? 1 : 0),
                            message->id, topic, (unsigned char *)message->payload, message->payload_len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // send packet
  err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  if (message->qos == LWMQTT_QOS1) {
    // wait for connack packet
    lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
    err = lwmqtt_cycle_until(c, &packet, LWMQTT_PUBACK_PACKET);
    if (err != LWMQTT_SUCCESS) {
      return err;
    } else if (packet != LWMQTT_PUBACK_PACKET) {
      return LWMQTT_FAILURE;
    }

    // decode packet
    bool dup;
    unsigned short packet_id;
    err = lwmqtt_decode_ack(&packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
    if (err != LWMQTT_SUCCESS) {
      return err;
    }
  } else if (message->qos == LWMQTT_QOS2) {
    // wait for connack packet
    lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
    err = lwmqtt_cycle_until(c, &packet, LWMQTT_PUBCOMP_PACKET);
    if (err != LWMQTT_SUCCESS) {
      return err;
    } else if (packet != LWMQTT_PUBCOMP_PACKET) {
      return LWMQTT_FAILURE;
    }

    // decode packet
    bool dup;
    unsigned short packet_id;
    err = lwmqtt_decode_ack(&packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
    if (err != LWMQTT_SUCCESS) {
      return err;
    }
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_client_disconnect(lwmqtt_client_t *c) {
  // set timer
  c->timer_set(c, c->timer_network_ref, c->command_timeout);

  // encode disconnect packet
  int len;
  if (lwmqtt_encode_zero(c->write_buf, c->write_buf_size, &len, LWMQTT_DISCONNECT_PACKET) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // set connected flag
  c->is_connected = 0;

  // send disconnected packet
  lwmqtt_err_t err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}
