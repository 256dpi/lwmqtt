#include <string.h>
#include <stdbool.h>

#include "packet.h"
#include "helpers.h"

int lwmqtt_encode_remaining_length(unsigned char *buf, int rem_len) {
  int rc = 0;

  do {
    unsigned char d = (unsigned char)(rem_len % 128);
    rem_len /= 128;
    // if there are more digits to encode, set the top bit of this digit
    if (rem_len > 0) d |= 0x80;
    buf[rc++] = d;
  } while (rem_len > 0);

  return rc;
}

int lwmqtt_total_header_length(int rem_len) {
  int len = 1;  // header byte

  if (rem_len < 128) {
    return len + 1;
  } else if (rem_len < 16384) {
    return len + 2;
  } else if (rem_len < 2097151) {
    return len + 3;
  } else {
    return len + 4;
  }
}

// TODO: Increment pointer directly?
int lwmqtt_decode_remaining_length(unsigned char *buf, int *rem_len) {
  unsigned char c;
  int multiplier = 1;
  int len = 0;

  *rem_len = 0;
  do {
    len++;

    if (len > 4) {
      return LWMQTT_REMAINING_LENGTH_OVERFLOW;
    }

    c = buf[len - 1];

    *rem_len += (c & 127) * multiplier;
    multiplier *= 128;
  } while ((c & 128) != 0);

  return len;
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

lwmqtt_err_t lwmqtt_encode_connect(unsigned char *buf, int buf_len, int *len, lwmqtt_options_t *options,
                                   lwmqtt_will_t *will) {
  // prepare pointer
  unsigned char *ptr = buf;

  /* calculate remaining length */

  // fixed header is 10
  int rem_len = 10;

  // add client id
  rem_len += lwmqtt_strlen(options->client_id) + 2;

  // add will if present
  if (will != NULL) {
    rem_len += lwmqtt_strlen(will->topic) + 2 + will->payload_len + 2;
  }

  // add username if present
  if (options->username.c_string || options->username.lp_string.data) {
    rem_len += lwmqtt_strlen(options->username) + 2;

    // add password if present
    if (options->password.c_string || options->password.lp_string.data) {
      rem_len += lwmqtt_strlen(options->password) + 2;
    }
  }

  // check buffer capacity
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  /* encode packet */

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_CONNECT_PACKET;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);

  // write version
  lwmqtt_write_c_string(&ptr, "MQTT");
  lwmqtt_write_char(&ptr, 4);

  // prepare flags
  lwmqtt_connect_flags_t flags = {0};
  flags.bits.clean_session = options->clean_session ? 1 : 0;

  // set will flags if present
  if (will != NULL) {
    flags.bits.will = 1;
    flags.bits.will_qos = (unsigned int)will->qos;
    flags.bits.will_retain = will->retained ? 1 : 0;
  }

  // set username flag if present
  if (options->username.c_string || options->username.lp_string.data) {
    flags.bits.username = 1;

    // set password flag if present
    if (options->password.c_string || options->password.lp_string.data) {
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
    lwmqtt_write_int(&ptr, will->payload_len);
    memcpy(ptr, will->payload, will->payload_len);
    ptr += will->payload_len;
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

lwmqtt_err_t lwmqtt_decode_connack(bool *session_present, lwmqtt_connack_t *connack_rc, unsigned char *buf,
                                   int buf_len) {
  // prepare pointer
  unsigned char *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_CONNACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // read remaining length
  int len;
  int rc = lwmqtt_decode_remaining_length(ptr, &len);
  if (rc == LWMQTT_REMAINING_LENGTH_OVERFLOW) {
    return LWMQTT_REMAINING_LENGTH_OVERFLOW;
  }

  // check lengths
  if (len != 2 || buf_len < len + 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // advance pointer
  ptr++;

  // read flags
  lwmqtt_connack_flags_t flags;
  flags.byte = lwmqtt_read_char(&ptr);
  *session_present = flags.bits.session_present == 1;
  *connack_rc = (lwmqtt_connack_t)lwmqtt_read_char(&ptr);

  return LWMQTT_SUCCESS;
}

static lwmqtt_err_t lwmqtt_encode_zero(unsigned char *buf, int buf_len, int *len, unsigned char packet_type) {
  // prepare pointer
  unsigned char *ptr = buf;

  // check buffer length
  if (buf_len < 2) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = packet_type;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  ptr += lwmqtt_encode_remaining_length(ptr, 0);

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_disconnect(unsigned char *buf, int buf_len, int *len) {
  return lwmqtt_encode_zero(buf, buf_len, len, LWMQTT_DISCONNECT_PACKET);
}

lwmqtt_err_t lwmqtt_encode_pingreq(unsigned char *buf, int buf_len, int *len) {
  return lwmqtt_encode_zero(buf, buf_len, len, LWMQTT_PINGREQ_PACKET);
}
