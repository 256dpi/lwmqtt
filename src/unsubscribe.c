#include "unsubscribe.h"
#include "packet.h"

int lwmqtt_encode_unsubscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id, int count,
                              lwmqtt_string_t *topic_filters) {
  unsigned char *ptr = buf;

  int rem_len = 2;

  for (int i = 0; i < count; ++i) {
    rem_len += 2 + lwmqtt_strlen(topic_filters[i]);  // length + topic
  }

  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_UNSUBSCRIBE_PACKET;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);  // write remaining length

  lwmqtt_write_int(&ptr, packet_id);

  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
  }

  return (int)(ptr - buf);
}

int lwmqtt_decode_unsuback(unsigned short *packet_id, unsigned char *buf, int buf_len) {
  lwmqtt_packet_t type;
  bool dup;

  // decode packet
  int err = lwmqtt_decode_ack(&type, &dup, packet_id, buf, buf_len);
  if (err != LWMQTT_SUCCESS) {
    return err;
  }

  // check type
  if (type != LWMQTT_UNSUBACK_PACKET) {
    return LWMQTT_FAILURE;
  }

  return 1;
}
