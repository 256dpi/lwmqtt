#include <string.h>

#include "client.h"

void lwmqtt_init(lwmqtt_client_t *c, unsigned char *write_buf, int write_buf_size, unsigned char *read_buf,
                 int read_buf_size) {
  c->next_packet_id = 1;
  c->keep_alive_interval = 0;
  c->ping_outstanding = false;
  c->is_connected = false;

  c->write_buf = write_buf;
  c->write_buf_size = write_buf_size;
  c->read_buf = read_buf;
  c->read_buf_size = read_buf_size;
  c->callback = NULL;

  c->network_ref = NULL;
  c->network_read = NULL;
  c->network_write = NULL;

  c->timer_keep_alive_ref = NULL;
  c->timer_network_ref = NULL;
  c->timer_set = NULL;
  c->timer_get = NULL;
}

void lwmqtt_set_network(lwmqtt_client_t *c, void *ref, lwmqtt_network_read_t read, lwmqtt_network_write_t write) {
  c->network_ref = ref;
  c->network_read = read;
  c->network_write = write;
}

void lwmqtt_set_timers(lwmqtt_client_t *c, void *keep_alive_ref, void *network_ref, lwmqtt_timer_set_t set,
                       lwmqtt_timer_get_t get) {
  c->timer_keep_alive_ref = keep_alive_ref;
  c->timer_network_ref = network_ref;
  c->timer_set = set;
  c->timer_get = get;

  c->timer_set(c, c->timer_keep_alive_ref, 0);
  c->timer_set(c, c->timer_network_ref, 0);
}

void lwmqtt_set_callback(lwmqtt_client_t *c, lwmqtt_callback_t cb) { c->callback = cb; }

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
    lwmqtt_err_t err = c->network_write(c, c->network_ref, &c->write_buf[sent], length, &sent,
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
  c->ping_outstanding = true;

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

  switch (*packet) {
    // handle publish packets
    case LWMQTT_PUBLISH_PACKET: {
      // decode publish packet
      lwmqtt_string_t topic = lwmqtt_default_string;
      lwmqtt_message_t msg;
      err = lwmqtt_decode_publish(&msg.dup, &msg.qos, &msg.retained, &msg.id, &topic, (unsigned char **)&msg.payload,
                                  &msg.payload_len, c->read_buf, c->read_buf_size);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // call callback if set
      if (c->callback != NULL) {
        c->callback(c, &topic, &msg);
      }

      // break early of qos zero
      if (msg.qos == LWMQTT_QOS0) {
        break;
      }

      // define ack packet
      lwmqtt_packet_t ack = LWMQTT_NO_PACKET;
      if (msg.qos == LWMQTT_QOS1) {
        ack = LWMQTT_PUBREC_PACKET;
      } else if (msg.qos == LWMQTT_QOS2) {
        ack = LWMQTT_PUBREL_PACKET;
      }

      // encode ack packet
      int len;
      err = lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, ack, false, msg.id);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // send ack packet
      err = lwmqtt_send_packet(c, len);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      break;
    }

    // handle pubrec packets
    case LWMQTT_PUBREC_PACKET: {
      // decode pubrec packet
      bool dup;
      unsigned short packet_id;
      err = lwmqtt_decode_ack(packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // encode pubrel packet
      int len;
      err = lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, LWMQTT_PUBREL_PACKET, 0, packet_id);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // send pubrel packet
      err = lwmqtt_send_packet(c, len);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      break;
    }

    // handle pubrel packets
    case LWMQTT_PUBREL_PACKET: {
      // decode pubrec packet
      bool dup;
      unsigned short packet_id;
      err = lwmqtt_decode_ack(packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // encode pubcomp packet
      int len;
      err = lwmqtt_encode_ack(c->write_buf, c->write_buf_size, &len, LWMQTT_PUBCOMP_PACKET, 0, packet_id);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      // send pubcomp packet
      err = lwmqtt_send_packet(c, len);
      if (err != LWMQTT_SUCCESS) {
        return err;
      }

      break;
    }

    // handle pingresp packets
    case LWMQTT_PINGRESP_PACKET: {
      // set flag
      c->ping_outstanding = false;

      break;
    }

    // handle all other packets
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

lwmqtt_err_t lwmqtt_yield(lwmqtt_client_t *c, unsigned int timeout) {
  // set timeout
  c->timer_set(c, c->timer_network_ref, timeout);

  // cycle until timeout has been reached
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  lwmqtt_err_t err = lwmqtt_cycle_until(c, &packet, LWMQTT_NO_PACKET);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_connect(lwmqtt_client_t *c, lwmqtt_options_t *options, lwmqtt_will_t *will,
                            lwmqtt_connack_t *connack, unsigned int timeout) {
  // return immediately if already connected
  if (c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timer to command timeout
  c->timer_set(c, c->timer_network_ref, timeout);

  // save keep alive interval
  c->keep_alive_interval = options->keep_alive;

  // set keep alive timer
  if (c->keep_alive_interval > 0) {
    c->timer_set(c, c->timer_keep_alive_ref, c->keep_alive_interval * 1000);
  }

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
  c->is_connected = true;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_subscribe(lwmqtt_client_t *c, const char *topic_filter, lwmqtt_qos_t qos, unsigned int timeout) {
  // immediately return error if not connected
  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timeout
  c->timer_set(c, c->timer_network_ref, timeout);

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

lwmqtt_err_t lwmqtt_unsubscribe(lwmqtt_client_t *c, const char *topic, unsigned int timeout) {
  // immediately return error if not connected
  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // set timer
  c->timer_set(c, c->timer_network_ref, timeout);

  // prepare string
  lwmqtt_string_t str = lwmqtt_default_string;
  str.c_string = (char *)topic;

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

lwmqtt_err_t lwmqtt_publish(lwmqtt_client_t *c, const char *topicName, lwmqtt_message_t *message,
                            unsigned int timeout) {
  // immediately return error if not connected
  if (!c->is_connected) {
    return LWMQTT_FAILURE;
  }

  // prepare string
  lwmqtt_string_t str = lwmqtt_default_string;
  str.c_string = (char *)topicName;

  // set timer
  c->timer_set(c, c->timer_network_ref, timeout);

  // add packet id if at least qos 1
  if (message->qos == LWMQTT_QOS1 || message->qos == LWMQTT_QOS2) {
    message->id = lwmqtt_get_next_packet_id(c);
  }

  // encode publish packet
  int len = 0;
  lwmqtt_err_t err =
      lwmqtt_encode_publish(c->write_buf, c->write_buf_size, &len, 0, message->qos, (char)(message->retained ? 1 : 0),
                            message->id, str, (unsigned char *)message->payload, message->payload_len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // send packet
  err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // immediately return on qos zero
  if(message->qos == LWMQTT_QOS0) {
    return LWMQTT_SUCCESS;
  }

  // define ack packet
  lwmqtt_packet_t ack = LWMQTT_NO_PACKET;
  if (message->qos == LWMQTT_QOS1) {
    ack = LWMQTT_PUBACK_PACKET;
  } else if (message->qos == LWMQTT_QOS2) {
    ack = LWMQTT_PUBCOMP_PACKET;
  }

  // wait for ack packet
  lwmqtt_packet_t packet = LWMQTT_NO_PACKET;
  err = lwmqtt_cycle_until(c, &packet, ack);
  if (err != LWMQTT_SUCCESS) {
    return err;
  } else if (packet != ack) {
    return LWMQTT_FAILURE;
  }

  // decode ack packet
  bool dup;
  unsigned short packet_id;
  err = lwmqtt_decode_ack(&packet, &dup, &packet_id, c->read_buf, c->read_buf_size);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_disconnect(lwmqtt_client_t *c, unsigned int timeout) {
  // set timer
  c->timer_set(c, c->timer_network_ref, timeout);

  // encode disconnect packet
  int len;
  if (lwmqtt_encode_zero(c->write_buf, c->write_buf_size, &len, LWMQTT_DISCONNECT_PACKET) != LWMQTT_SUCCESS) {
    return LWMQTT_FAILURE;
  }

  // set connected flag
  c->is_connected = false;

  // send disconnected packet
  lwmqtt_err_t err = lwmqtt_send_packet(c, len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  return LWMQTT_SUCCESS;
}
