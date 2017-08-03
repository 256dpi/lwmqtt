#include <lwmqtt.h>
#include <string.h>

#include "packet.h"

typedef union {
  unsigned char byte;
  struct {
    unsigned int retain : 1;
    unsigned int qos : 2;
    unsigned int dup : 1;
    unsigned int type : 4;
  } bits;
} lwmqtt_header_t;

// TODO: Move to helpers?
static int lwmqtt_total_header_length(int rem_len) {
  if (rem_len < 128) {
    return 1 + 1;
  } else if (rem_len < 16384) {
    return 1 + 2;
  } else if (rem_len < 2097151) {
    return 1 + 3;
  } else {
    return 1 + 4;
  }
}

lwmqtt_err_t lwmqtt_detect_packet_type(void *buf, lwmqtt_packet_type_t *packet_type) {
  // prepare pointer
  void *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);

  // check if packet type is correct and can be received
  switch ((lwmqtt_packet_type_t)header.bits.type) {
    case LWMQTT_CONNACK_PACKET:
    case LWMQTT_PUBLISH_PACKET:
    case LWMQTT_PUBACK_PACKET:
    case LWMQTT_PUBREC_PACKET:
    case LWMQTT_PUBREL_PACKET:
    case LWMQTT_PUBCOMP_PACKET:
    case LWMQTT_SUBACK_PACKET:
    case LWMQTT_UNSUBACK_PACKET:
    case LWMQTT_PINGRESP_PACKET:
      *packet_type = (lwmqtt_packet_type_t)header.bits.type;
      return LWMQTT_SUCCESS;
    default:
      *packet_type = LWMQTT_NO_PACKET;
      return LWMQTT_DECODE_ERROR;
  }
}

lwmqtt_err_t lwmqtt_detect_remaining_length(void *buf, int buf_len, int *rem_len) {
  // prepare pointer
  void *ptr = buf;

  // attempt to decode remaining length
  *rem_len = lwmqtt_read_varnum(&ptr, buf_len);
  if (*rem_len == -1) {
    return LWMQTT_BUFFER_TOO_SHORT;
  } else if (*rem_len == -2) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  return LWMQTT_SUCCESS;
}

typedef union {
  unsigned char byte;
  struct {
    unsigned int _ : 1;
    unsigned int clean_session : 1;
    unsigned int will : 1;
    unsigned int will_qos : 2;
    unsigned int will_retain : 1;
    unsigned int password : 1;
    unsigned int username : 1;
  } bits;
} lwmqtt_connect_flags_t;

typedef union {
  unsigned char byte;
  struct {
    unsigned int _ : 7;
    unsigned int session_present : 1;
  } bits;
} lwmqtt_connack_flags_t;

lwmqtt_err_t lwmqtt_encode_connect(void *buf, int buf_len, int *len, lwmqtt_options_t *options, lwmqtt_will_t *will) {
  // prepare pointer
  void *ptr = buf;

  /* calculate remaining length */

  // fixed header is 10
  int rem_len = 10;

  // add client id
  rem_len += options->client_id.len + 2;

  // add will if present
  if (will != NULL) {
    rem_len += will->topic.len + 2 + will->message.payload_len + 2;
  }

  // add username if present
  if (options->username.len > 0) {
    rem_len += options->username.len + 2;

    // add password if present
    if (options->password.len > 0) {
      rem_len += options->password.len + 2;
    }
  }

  // check buffer capacity
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  /* encode packet */

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_CONNECT_PACKET;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, rem_len);

  // write version
  lwmqtt_write_string(&ptr, lwmqtt_str("MQTT"));
  lwmqtt_write_char(&ptr, 4);

  // prepare flags
  lwmqtt_connect_flags_t flags = {0};
  flags.bits.clean_session = options->clean_session ? 1 : 0;

  // set will flags if present
  if (will != NULL) {
    flags.bits.will = 1;
    flags.bits.will_qos = (unsigned int)will->message.qos;
    flags.bits.will_retain = will->message.retained ? 1 : 0;
  }

  // set username flag if present
  if (options->username.len > 0) {
    flags.bits.username = 1;

    // set password flag if present
    if (options->password.len > 0) {
      flags.bits.password = 1;
    }
  }

  // write flags
  lwmqtt_write_char(&ptr, flags.byte);

  // write keep alive
  lwmqtt_write_int(&ptr, options->keep_alive);

  // write client id
  lwmqtt_write_string(&ptr, options->client_id);

  // write will topic and payload if present
  if (will != NULL) {
    lwmqtt_write_string(&ptr, will->topic);
    lwmqtt_write_int(&ptr, will->message.payload_len);
    memcpy(ptr, will->message.payload, will->message.payload_len);
    ptr += will->message.payload_len;
  }

  // write username if present
  if (flags.bits.username) {
    lwmqtt_write_string(&ptr, options->username);

    // write password if present
    if (flags.bits.password) {
      lwmqtt_write_string(&ptr, options->password);
    }
  }

  // set written length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_decode_connack(bool *session_present, lwmqtt_return_code_t *return_code, void *buf, int buf_len) {
  // prepare pointer
  void *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_CONNACK_PACKET) {
    return LWMQTT_DECODE_ERROR;
  }

  // read remaining length
  int rem_len = lwmqtt_read_varnum(&ptr, buf_len - 1);
  if (rem_len == -1) {
    return LWMQTT_BUFFER_TOO_SHORT;
  } else if (rem_len == -2) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  // check lengths
  if (rem_len != 2 || buf_len < rem_len + 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // read flags
  lwmqtt_connack_flags_t flags;
  flags.byte = lwmqtt_read_char(&ptr);
  *session_present = flags.bits.session_present == 1;
  *return_code = (lwmqtt_return_code_t)lwmqtt_read_char(&ptr);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_zero(void *buf, int buf_len, int *len, lwmqtt_packet_type_t packet_type) {
  // prepare pointer
  void *ptr = buf;

  // check buffer length
  if (buf_len < 2) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = packet_type;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, 0);

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_decode_ack(lwmqtt_packet_type_t *packet_type, bool *dup, unsigned short *packet_id, void *buf,
                               int buf_len) {
  // prepare pointer
  void *ptr = buf;

  // read header
  lwmqtt_header_t header = {0};
  header.byte = lwmqtt_read_char(&ptr);
  *dup = header.bits.dup == 1;
  *packet_type = (lwmqtt_packet_type_t)header.bits.type;

  // read remaining length
  int rem_len = lwmqtt_read_varnum(&ptr, buf_len - 1);
  if (rem_len == -1) {
    return LWMQTT_BUFFER_TOO_SHORT;
  } else if (rem_len == -2) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  // check lengths
  if (rem_len != 2 || buf_len < rem_len + 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // read packet id
  *packet_id = (unsigned short)lwmqtt_read_int(&ptr);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_ack(void *buf, int buf_len, int *len, lwmqtt_packet_type_t packet_type, bool dup,
                               unsigned short packet_id) {
  // prepare pointer
  void *ptr = buf;

  // check buffer size
  if (buf_len < 4) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = packet_type;
  header.bits.dup = dup ? 1 : 0;
  header.bits.qos = (packet_type == LWMQTT_PUBREL_PACKET) ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, 2);

  // write packet id
  lwmqtt_write_int(&ptr, packet_id);

  // set written length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_decode_publish(bool *dup, lwmqtt_qos_t *qos, bool *retained, unsigned short *packet_id,
                                   lwmqtt_string_t *topic, void **payload, int *payload_len, void *buf, int buf_len) {
  // prepare pointer
  void *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_PUBLISH_PACKET) {
    return LWMQTT_DECODE_ERROR;
  }

  // set dup
  *dup = header.bits.dup == 1;

  // set qos
  *qos = (lwmqtt_qos_t)header.bits.qos;

  // set retained
  *retained = header.bits.retain == 1;

  // read remaining length
  int rem_len = lwmqtt_read_varnum(&ptr, buf_len - 1);
  if (rem_len == -1) {
    return LWMQTT_BUFFER_TOO_SHORT;
  } else if (rem_len == -2) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  // check lengths
  if (buf_len < rem_len + 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // calculate end pointer
  void *end_ptr = ptr + rem_len;

  // do we have enough data to read the topic?
  if (!lwmqtt_read_string(topic, &ptr, end_ptr) || end_ptr - ptr < 0) {
    return LWMQTT_DECODE_ERROR;
  }

  // read packet id if qos is at least 1
  if (*qos > 0) {
    *packet_id = (unsigned short)lwmqtt_read_int(&ptr);
  } else {
    *packet_id = 0;
  }

  // set payload
  *payload_len = (int)(end_ptr - ptr);
  *payload = ptr;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_publish(void *buf, int buf_len, int *len, bool dup, lwmqtt_qos_t qos, bool retained,
                                   unsigned short packet_id, lwmqtt_string_t topic, void *payload, int payload_len) {
  // prepare pointer
  void *ptr = buf;

  // prepare remaining length
  int rem_len = 2 + topic.len + payload_len;

  // add packet id if qos is at least 1
  if (qos > 0) {
    rem_len += 2;
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_PUBLISH_PACKET;
  header.bits.dup = dup ? 1 : 0;
  header.bits.qos = (unsigned int)qos;
  header.bits.retain = retained ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, rem_len);

  // write topic
  lwmqtt_write_string(&ptr, topic);

  // write packet id if qos is at least 1
  if (qos > 0) {
    lwmqtt_write_int(&ptr, packet_id);
  }

  // write payload
  memcpy(ptr, payload, payload_len);
  ptr += payload_len;

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_subscribe(void *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                     lwmqtt_string_t *topic_filters, lwmqtt_qos_t *qos_levels) {
  // prepare pointer
  void *ptr = buf;

  // prepare remaining length
  int rem_len = 2;

  // add all topics
  for (int i = 0; i < count; i++) {
    rem_len += 2 + topic_filters[i].len + 1;
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_SUBSCRIBE_PACKET;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, rem_len);

  // write packet id
  lwmqtt_write_int(&ptr, packet_id);

  // write all topics
  for (int i = 0; i < count; i++) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
    lwmqtt_write_char(&ptr, (unsigned char)qos_levels[i]);
  }

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_decode_suback(unsigned short *packet_id, int max_count, int *count,
                                  lwmqtt_qos_t *granted_qos_levels, void *buf, int buf_len) {
  // prepare pointer
  void *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_SUBACK_PACKET) {
    return LWMQTT_DECODE_ERROR;
  }

  // read remaining length
  int rem_len = lwmqtt_read_varnum(&ptr, buf_len - 1);
  if (rem_len == -1) {
    return LWMQTT_BUFFER_TOO_SHORT;
  } else if (rem_len == -2) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  void *end_ptr = ptr + rem_len;

  if (end_ptr - ptr < 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // read packet id
  *packet_id = (unsigned short)lwmqtt_read_int(&ptr);

  // read all suback codes
  *count = 0;
  while (ptr < end_ptr) {
    if (*count > max_count) {
      return LWMQTT_DECODE_ERROR;
    }

    granted_qos_levels[(*count)++] = (lwmqtt_qos_t)lwmqtt_read_char(&ptr);
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_unsubscribe(void *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                       lwmqtt_string_t *topic_filters) {
  // prepare pointer
  void *ptr = buf;

  // prepare remaining length
  int rem_len = 2;

  // add all topics
  for (int i = 0; i < count; i++) {
    rem_len += 2 + topic_filters[i].len;
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_UNSUBSCRIBE_PACKET;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  lwmqtt_write_varnum(&ptr, rem_len);

  // write packet id
  lwmqtt_write_int(&ptr, packet_id);

  // write topics
  for (int i = 0; i < count; i++) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
  }

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}
