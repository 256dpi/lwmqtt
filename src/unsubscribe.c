#include "unsubscribe.h"

lwmqtt_err_t lwmqtt_encode_unsubscribe(unsigned char *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                       lwmqtt_string_t *topic_filters) {
  // prepare pointer
  unsigned char *ptr = buf;

  // prepare remaining length
  int rem_len = 2;

  // add all topics
  for (int i = 0; i < count; i++) {
    rem_len += 2 + lwmqtt_strlen(topic_filters[i]);
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_UNSUBSCRIBE_PACKET;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);

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
