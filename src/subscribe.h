#ifndef LWMQTT_SUBSCRIBE_H
#define LWMQTT_SUBSCRIBE_H

#include "helpers.h"

/**
  * Encodes the supplied subscribe data into the supplied buffer, ready for sending
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packet_id integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters and reqQos arrays
  * @param topic_filters - array of topic filter names
  * @param qos_levels - array of requested QoS
  * @return the length of the encoded data.  <= 0 indicates error
  */
int lwmqtt_encode_subscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id, int count,
                            lwmqtt_string_t *topic_filters, int *qos_levels);

/**
  * Decodes the supplied (wire) buffer into suback data
  *
  * @param packet_id returned integer - the MQTT packet identifier
  * @param max_count - the maximum number of members allowed in the grantedQoSs array
  * @param count returned integer - number of members in the grantedQoSs array
  * @param granted_qos_levels returned array of integers - the granted qualities of service
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_decode_suback(unsigned short *packet_id, int max_count, int *count, int *granted_qos_levels,
                         unsigned char *buf, int buf_len);

#endif  // LWMQTT_SUBSCRIBE_H
