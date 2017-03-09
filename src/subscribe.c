/*******************************************************************************
 * Copyright (c) 2014 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *******************************************************************************/

#include <string.h>

#include "packet.h"

/**
  * Determines the length of the MQTT subscribe packet that would be produced using the supplied parameters
  * @param count the number of topic filter strings in topicFilters
  * @param topicFilters the array of topic filter strings to be used in the publish
  * @return the length of buffer needed to contain the serialized version of the packet
  */
int MQTTSerialize_subscribeLength(int count, lwmqtt_string_t topicFilters[]) {
  int i;
  int len = 2; /* packetid */

  for (i = 0; i < count; ++i) len += 2 + lwmqtt_strlen(topicFilters[i]) + 1; /* length + topic + req_qos */
  return len;
}

/**
  * Serializes the supplied subscribe data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied bufferr
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters and reqQos arrays
  * @param topicFilters - array of topic filter names
  * @param requestedQoSs - array of requested QoS
  * @return the length of the serialized data.  <= 0 indicates error
  */
int lwmqtt_serialize_subscribe(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid, int count,
                               lwmqtt_string_t *topicFilters, int *requestedQoSs) {
  unsigned char* ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;
  int rc = 0;
  int i = 0;

  if (lwmqtt_packet_len(rem_len = MQTTSerialize_subscribeLength(count, topicFilters)) > buflen) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    goto exit;
  }

  header.byte = 0;
  header.bits.type = SUBSCRIBE;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, rem_len); /* write remaining length */
  ;

  lwmqtt_write_int(&ptr, packetid);

  for (i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topicFilters[i]);
    lwmqtt_write_char(&ptr, requestedQoSs[i]);
  }

  rc = ptr - buf;
exit:
  return rc;
}

/**
  * Deserializes the supplied (wire) buffer into suback data
  * @param packetid returned integer - the MQTT packet identifier
  * @param maxcount - the maximum number of members allowed in the grantedQoSs array
  * @param count returned integer - number of members in the grantedQoSs array
  * @param grantedQoSs returned array of integers - the granted qualities of service
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_suback(unsigned short *packetid, int maxcount, int *count, int *grantedQoSs, unsigned char *buf,
                              int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char* curdata = buf;
  unsigned char* enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != SUBACK) goto exit;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;
  if (enddata - curdata < 2) goto exit;

  *packetid = lwmqtt_read_int(&curdata);

  *count = 0;
  while (curdata < enddata) {
    if (*count > maxcount) {
      rc = -1;
      goto exit;
    }
    grantedQoSs[(*count)++] = lwmqtt_read_char(&curdata);
  }

  rc = 1;
exit:
  return rc;
}
