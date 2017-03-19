#include "subscribe.h"
#include "helpers.h"
#include "packet.h"

int lwmqtt_encode_subscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id, int count,
                            lwmqtt_string_t *topic_filters, int *qos_levels) {
  unsigned char *ptr = buf;

  int rem_len = 2;  // packet id

  for (int i = 0; i < count; ++i) {
    rem_len += 2 + lwmqtt_strlen(topic_filters[i]) + 1;  // length + topic + req_qos
  }

  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_SUBSCRIBE_PACKET;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);  // write remaining length

  lwmqtt_write_int(&ptr, packet_id);

  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
    lwmqtt_write_char(&ptr, (unsigned char)qos_levels[i]);
  }

  return (int)(ptr - buf);
}

int lwmqtt_decode_suback(unsigned short *packet_id, int max_count, int *count, int *granted_qos_levels,
                         unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *cur_ptr = buf;
  int rc = 0;
  int len;

  header.byte = lwmqtt_read_char(&cur_ptr);
  if (header.bits.type != LWMQTT_SUBACK_PACKET) {
    return rc;
  }

  cur_ptr += (rc = lwmqtt_decode_remaining_length(cur_ptr, &len));  // read remaining length
  unsigned char *end_ptr = cur_ptr + len;
  if (end_ptr - cur_ptr < 2) {
    return rc;
  }

  *packet_id = (unsigned short)lwmqtt_read_int(&cur_ptr);

  *count = 0;
  while (cur_ptr < end_ptr) {
    if (*count > max_count) {
      return -1;
    }

    granted_qos_levels[(*count)++] = lwmqtt_read_char(&cur_ptr);
  }

  return 1;
}
