#include "subscribe.h"

lwmqtt_err_t lwmqtt_encode_subscribe(unsigned char *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                     lwmqtt_string_t *topic_filters, lwmqtt_qos_t *qos_levels) {
  // prepare pointer
  unsigned char *ptr = buf;

  // prepare remaining length
  int rem_len = 2;

  // add all topics
  for (int i = 0; i < count; ++i) {
    rem_len += 2 + lwmqtt_strlen(topic_filters[i]) + 1;
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_SUBSCRIBE_PACKET;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  // write remaining length
  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);

  // write packet id
  lwmqtt_write_int(&ptr, packet_id);

  // write all topics
  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
    lwmqtt_write_char(&ptr, (unsigned char)qos_levels[i]);
  }

  // set length
  *len = (int)(ptr - buf);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_decode_suback(unsigned short *packet_id, int max_count, int *count, int *granted_qos_levels,
                                  unsigned char *buf, int buf_len) {
  // prepare pointer
  unsigned char *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_SUBACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  // read remaining length
  int rem_len;
  int rc = lwmqtt_decode_remaining_length(ptr, &rem_len);
  ptr += rc;

  unsigned char *end_ptr = ptr + rem_len;

  if (end_ptr - ptr < 2) {
    return LWMQTT_LENGTH_MISMATCH;
  }

  // read packet id
  *packet_id = (unsigned short)lwmqtt_read_int(&ptr);

  // read all suback codes
  *count = 0;
  while (ptr < end_ptr) {
    if (*count > max_count) {
      return LWMQTT_FAILURE;
    }

    granted_qos_levels[(*count)++] = lwmqtt_read_char(&ptr);
  }

  return LWMQTT_SUCCESS;
}
