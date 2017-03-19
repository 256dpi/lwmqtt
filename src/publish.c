#include <string.h>

#include "helpers.h"
#include "packet.h"
#include "publish.h"

int lwmqtt_decode_publish(bool *dup, int *qos, bool *retained, unsigned short *packet_id, lwmqtt_string_t *topic,
                          unsigned char **payload, int *payload_len, unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *cur_ptr = buf;
  int rc = 0;
  int len = 0;

  header.byte = lwmqtt_read_char(&cur_ptr);
  if (header.bits.type != LWMQTT_PUBLISH_PACKET) {
    return rc;
  }

  *dup = header.bits.dup == 1;
  *qos = header.bits.qos;
  *retained = header.bits.retain == 1;

  cur_ptr += (rc = lwmqtt_decode_remaining_length(cur_ptr, &len));  // read remaining length
  unsigned char *end_ptr = cur_ptr + len;

  // do we have enough data to read the protocol version byte?
  if (!lwmqtt_read_lp_string(topic, &cur_ptr, end_ptr) || end_ptr - cur_ptr < 0) {
    return rc;
  }

  if (*qos > 0) {
    *packet_id = (unsigned short)lwmqtt_read_int(&cur_ptr);
  }

  *payload_len = (int)(end_ptr - cur_ptr);
  *payload = cur_ptr;
  rc = 1;

  return rc;
}

int lwmqtt_encode_publish(unsigned char *buf, int buf_len, unsigned char dup, int qos, unsigned char retained,
                          unsigned short packet_id, lwmqtt_string_t topic, unsigned char *payload, int payload_len) {
  unsigned char *ptr = buf;

  int rem_len = 0;

  rem_len += 2 + lwmqtt_strlen(topic) + payload_len;
  if (qos > 0) {
    rem_len += 2;
  }  // packet id

  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_PUBLISH_PACKET;
  header.bits.dup = dup;
  header.bits.qos = (unsigned int)qos;
  header.bits.retain = retained;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);  // write remaining length

  lwmqtt_write_string(&ptr, topic);

  if (qos > 0) {
    lwmqtt_write_int(&ptr, packet_id);
  }

  memcpy(ptr, payload, payload_len);
  ptr += payload_len;

  return (int)(ptr - buf);
}
