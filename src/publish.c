#include <string.h>

#include "helpers.h"
#include "packet.h"
#include "publish.h"

lwmqtt_err_t lwmqtt_decode_publish(bool *dup, lwmqtt_qos_t *qos, bool *retained, unsigned short *packet_id,
                                   lwmqtt_string_t *topic, unsigned char **payload, int *payload_len,
                                   unsigned char *buf, int buf_len) {
  // prepare pointer
  unsigned char *ptr = buf;

  // read header
  lwmqtt_header_t header;
  header.byte = lwmqtt_read_char(&ptr);
  if (header.bits.type != LWMQTT_PUBLISH_PACKET) {
    return LWMQTT_FAILURE;
  }

  // set dup
  *dup = header.bits.dup == 1;

  // set qos
  *qos = (lwmqtt_qos_t)header.bits.qos;

  // set retained
  *retained = header.bits.retain == 1;

  // read remaining length
  int rem_len = 0;
  int rc = lwmqtt_decode_remaining_length(ptr, &rem_len);
  ptr += rc;

  // calculate end pointer
  unsigned char *end_ptr = ptr + rem_len;

  // do we have enough data to read the topic?
  if (!lwmqtt_read_lp_string(topic, &ptr, end_ptr) || end_ptr - ptr < 0) {
    return LWMQTT_FAILURE;
  }

  // read packet id if qos is at least 1
  if (*qos > 0) {
    *packet_id = (unsigned short)lwmqtt_read_int(&ptr);
  }

  // set payload
  *payload_len = (int)(end_ptr - ptr);
  *payload = ptr;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_encode_publish(unsigned char *buf, int buf_len, int *len, bool dup, lwmqtt_qos_t qos, bool retained,
                                   unsigned short packet_id, lwmqtt_string_t topic, unsigned char *payload,
                                   int payload_len) {
  // prepare pointer
  unsigned char *ptr = buf;

  // prepare remaining length
  int rem_len = 2 + lwmqtt_strlen(topic) + payload_len;

  // add packet id if qos is at least 1
  if (qos > 0) {
    rem_len += 2;
  }

  // check buffer size
  if (lwmqtt_total_header_length(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  // write header
  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_PUBLISH_PACKET;
  header.bits.dup = dup ? 1 : 0;
  header.bits.qos = (unsigned int)qos;
  header.bits.retain = retained ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte);

  // write remaining length
  ptr += lwmqtt_encode_remaining_length(ptr, rem_len);

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
