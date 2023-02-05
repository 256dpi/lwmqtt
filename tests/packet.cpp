#include <gtest/gtest.h>

extern "C" {
#include <lwmqtt.h>
#include "../src/packet.h"
}

#define EXPECT_ARRAY_EQ(reference, actual, element_count)                 \
  {                                                                       \
    for (size_t cmp_i = 0; cmp_i < element_count; cmp_i++) {              \
      EXPECT_EQ(reference[cmp_i], actual[cmp_i]) << "At byte: " << cmp_i; \
    }                                                                     \
  }

TEST(Packet, DetectPacketType) {
  uint8_t h = LWMQTT_CONNACK_PACKET << 4u;
  lwmqtt_packet_type_t p;
  lwmqtt_err_t err = lwmqtt_detect_packet_type(&h, 1, &p);
  EXPECT_EQ(p, LWMQTT_CONNACK_PACKET);
  EXPECT_EQ(err, LWMQTT_SUCCESS);
}

TEST(Packet, DetectPacketTypeError) {
  uint8_t h = 255;
  lwmqtt_packet_type_t p;
  lwmqtt_err_t err = lwmqtt_detect_packet_type(&h, 1, &p);
  EXPECT_EQ(p, LWMQTT_NO_PACKET);
  EXPECT_EQ(err, LWMQTT_MISSING_OR_WRONG_PACKET);
}

TEST(Packet, DetectRemainingLength1) {
  uint8_t h = 60;
  uint32_t rem_len = 0;
  lwmqtt_err_t err = lwmqtt_detect_remaining_length(&h, 1, &rem_len);
  EXPECT_EQ(rem_len, (uint32_t)60);
  EXPECT_EQ(err, LWMQTT_SUCCESS);
}

TEST(Packet, DetectRemainingLength2) {
  uint8_t h[2] = {255, 60};
  uint32_t rem_len = 0;
  lwmqtt_err_t err = lwmqtt_detect_remaining_length(h, sizeof(h), &rem_len);
  EXPECT_EQ(rem_len, (uint32_t)7807);
  EXPECT_EQ(err, LWMQTT_SUCCESS);
}

TEST(Packet, DetectRemainingLengthError) {
  uint8_t h = 255;
  uint32_t rem_len = 0;
  lwmqtt_err_t err = lwmqtt_detect_remaining_length(&h, 1, &rem_len);
  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, DetectRemainingLengthOverflow) {
  uint8_t h[5] = {255, 255, 255, 255, 255};
  uint32_t rem_len = 0;
  lwmqtt_err_t err = lwmqtt_detect_remaining_length(h, sizeof(h), &rem_len);
  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_OVERFLOW);
}

TEST(Packet, EncodeConnect1) {
  uint8_t pkt[60] = {
      LWMQTT_CONNECT_PACKET << 4u,
      58,
      0,  // protocol string MSB
      4,  // protocol string LSB
      'M',
      'Q',
      'T',
      'T',
      4,    // protocol level 4
      204,  // connect flags
      0,    // keep alive MSB
      10,   // keep alive LSB
      0,    // client ID MSB
      6,    // client ID LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // will topic MSB
      4,  // will topic LSB
      'w',
      'i',
      'l',
      'l',
      0,   // will message MSB
      12,  // will message LSB
      's',
      'e',
      'n',
      'd',
      ' ',
      'm',
      'e',
      ' ',
      'h',
      'o',
      'm',
      'e',
      0,  // username MSB
      6,  // username LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,   // password MSB
      10,  // password LSB
      'v',
      'e',
      'r',
      'y',
      's',
      'e',
      'c',
      'r',
      'e',
      't',
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_will_t will = lwmqtt_default_will;
  will.topic = lwmqtt_string("will");
  will.payload = lwmqtt_string("send me home");
  will.qos = LWMQTT_QOS1;

  lwmqtt_connect_options_t opts = lwmqtt_default_options;
  opts.clean_session = false;
  opts.keep_alive = 10;
  opts.client_id = lwmqtt_string("lwmqtt");
  opts.username = lwmqtt_string("lwmqtt");
  opts.password = lwmqtt_string("verysecret");

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, sizeof(pkt), &len, opts, &will);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeConnect2) {
  uint8_t pkt[14] = {
      LWMQTT_CONNECT_PACKET << 4u,
      12,
      0,  // protocol string MSB
      4,  // protocol string LSB
      'M',
      'Q',
      'T',
      'T',
      4,   // protocol level 4
      2,   // connect flags
      0,   // keep alive MSB
      60,  // keep alive LSB
      0,   // client ID MSB
      0,   // client ID LSB
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_connect_options_t opts = lwmqtt_default_options;

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, sizeof(pkt), &len, opts, nullptr);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeConnect3) {
  uint8_t pkt[50] = {
      LWMQTT_CONNECT_PACKET << 4u,
      48,
      0,  // protocol string MSB
      4,  // protocol string LSB
      'M',
      'Q',
      'T',
      'T',
      4,    // protocol level 4
      204,  // connect flags
      0,    // keep alive MSB
      10,   // keep alive LSB
      0,    // client ID MSB
      6,    // client ID LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // will topic MSB
      4,  // will topic LSB
      'w',
      'i',
      'l',
      'l',
      0,   // will message MSB
      12,  // will message LSB
      's',
      'e',
      'n',
      'd',
      ' ',
      'm',
      'e',
      ' ',
      'h',
      'o',
      'm',
      'e',
      0,  // username MSB
      0,  // username LSB
      0,  // password MSB
      6,  // password LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_will_t will = lwmqtt_default_will;
  will.topic = lwmqtt_string("will");
  will.payload = lwmqtt_string("send me home");
  will.qos = LWMQTT_QOS1;

  lwmqtt_connect_options_t opts = lwmqtt_default_options;
  opts.clean_session = false;
  opts.keep_alive = 10;
  opts.client_id = lwmqtt_string("lwmqtt");
  opts.password = lwmqtt_string("lwmqtt");

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, sizeof(pkt), &len, opts, &will);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeConnectError) {
  uint8_t buf[4];  // <- too small buffer

  lwmqtt_connect_options_t opts = lwmqtt_default_options;

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, sizeof(buf), &len, opts, nullptr);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, DecodeConnack) {
  uint8_t pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4u, 2,
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_return_code_t return_code;
  lwmqtt_err_t err = lwmqtt_decode_connack(pkt, sizeof(pkt), &session_present, &return_code);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(session_present, false);
  EXPECT_EQ(return_code, LWMQTT_CONNECTION_ACCEPTED);
}

TEST(Packet, DecodeConnackError1) {
  uint8_t pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4u,
      3,  // <-- wrong size
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_return_code_t return_code;
  lwmqtt_err_t err = lwmqtt_decode_connack(pkt, sizeof(pkt), &session_present, &return_code);

  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_MISMATCH);
}

TEST(Packet, DecodeConnackError2) {
  uint8_t pkt[3] = {
      LWMQTT_CONNACK_PACKET << 4u, 3,
      0,  // session not present
          // <- missing packet size
  };

  bool session_present;
  lwmqtt_return_code_t return_code;
  lwmqtt_err_t err = lwmqtt_decode_connack(pkt, sizeof(pkt), &session_present, &return_code);

  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_MISMATCH);
}

TEST(Packet, EncodeZero) {
  uint8_t pkt[2] = {LWMQTT_PINGREQ_PACKET << 4u, 0};

  uint8_t buf[sizeof(pkt)];

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_zero(buf, sizeof(pkt), &len, LWMQTT_PINGREQ_PACKET);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, DecodeAck) {
  uint8_t pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4u, 2,
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  uint16_t packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(pkt, sizeof(pkt), LWMQTT_PUBACK_PACKET, &packet_id);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(packet_id, 7);
}

TEST(Packet, DecodeAckError1) {
  uint8_t pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4u,
      1,  // <-- wrong remaining length
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  uint16_t packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(pkt, sizeof(pkt), LWMQTT_PUBACK_PACKET, &packet_id);

  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_MISMATCH);
}

TEST(Packet, DecodeAckError2) {
  uint8_t pkt[3] = {
      LWMQTT_PUBACK_PACKET << 4u,
      1,  // <-- wrong remaining length
      0,  // packet ID MSB
          //  <- insufficient bytes
  };

  uint16_t packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(pkt, sizeof(pkt), LWMQTT_PUBACK_PACKET, &packet_id);

  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_MISMATCH);
}

TEST(Packet, EncodeAck) {
  uint8_t pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4u, 2,
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  uint8_t buf[4];

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_ack(buf, sizeof(pkt), &len, LWMQTT_PUBACK_PACKET, 7);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeAckError) {
  uint8_t buf[2];  // <- too small buffer

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_ack(buf, sizeof(buf), &len, LWMQTT_PUBACK_PACKET, 7);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, DecodePublish1) {
  uint8_t pkt[24] = {
      LWMQTT_PUBLISH_PACKET << 4u | 11,
      22,
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // packet ID MSB
      7,  // packet ID LSB
      's',
      'e',
      'n',
      'd',
      ' ',
      'm',
      'e',
      ' ',
      'h',
      'o',
      'm',
      'e',
  };

  bool dup;
  uint16_t packet_id;
  lwmqtt_string_t topic;
  lwmqtt_message_t msg;
  lwmqtt_err_t err = lwmqtt_decode_publish(pkt, sizeof(pkt), &dup, &packet_id, &topic, &msg);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(dup, true);
  EXPECT_EQ(msg.qos, 1);
  EXPECT_EQ(msg.retained, true);
  EXPECT_EQ(packet_id, 7);
  EXPECT_ARRAY_EQ("lwmqtt", topic.data, 6);
  EXPECT_EQ(msg.payload_len, (size_t)12);
  EXPECT_ARRAY_EQ("send me home", msg.payload, 12);
}

TEST(Packet, DecodePublish2) {
  uint8_t pkt[22] = {
      LWMQTT_PUBLISH_PACKET << 4u,
      20,
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      's',
      'e',
      'n',
      'd',
      ' ',
      'm',
      'e',
      ' ',
      'h',
      'o',
      'm',
      'e',
  };

  bool dup;
  uint16_t packet_id;
  lwmqtt_string_t topic = lwmqtt_default_string;
  lwmqtt_message_t msg;
  lwmqtt_err_t err = lwmqtt_decode_publish(pkt, sizeof(pkt), &dup, &packet_id, &topic, &msg);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(dup, false);
  EXPECT_EQ(msg.qos, 0);
  EXPECT_EQ(msg.retained, false);
  EXPECT_EQ(packet_id, 0);
  EXPECT_ARRAY_EQ("lwmqtt", topic.data, 6);
  EXPECT_EQ(msg.payload_len, (size_t)12);
  EXPECT_ARRAY_EQ("send me home", msg.payload, 12);
}

TEST(Packet, DecodePublishError) {
  uint8_t pkt[2] = {
      LWMQTT_PUBLISH_PACKET << 4u,
      2,  // <-- too much
  };

  bool dup;
  uint16_t packet_id;
  lwmqtt_string_t topic = lwmqtt_default_string;
  lwmqtt_message_t msg;
  lwmqtt_err_t err = lwmqtt_decode_publish(pkt, sizeof(pkt), &dup, &packet_id, &topic, &msg);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, EncodePublish1) {
  uint8_t pkt[12] = {
      LWMQTT_PUBLISH_PACKET << 4u | 11,
      22,
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_string_t topic = lwmqtt_string("lwmqtt");
  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.qos = LWMQTT_QOS1;
  msg.payload = (uint8_t*)"send me home";
  msg.payload_len = 12;
  msg.retained = true;

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(pkt), &len, true, 7, topic, msg);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodePublish2) {
  uint8_t pkt[10] = {
      LWMQTT_PUBLISH_PACKET << 4u,
      20,
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_string_t topic = lwmqtt_string("lwmqtt");
  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.payload = (uint8_t*)"send me home";
  msg.payload_len = 12;

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(pkt), &len, false, 0, topic, msg);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodePublishError) {
  uint8_t buf[2];  // <- too small buffer

  lwmqtt_string_t topic = lwmqtt_string("lwmqtt");
  lwmqtt_message_t msg = lwmqtt_default_message;
  msg.payload = (uint8_t*)"send me home";
  msg.payload_len = 12;

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(buf), &len, false, 0, topic, msg);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, DecodeSuback) {
  uint8_t pkt[8] = {
      LWMQTT_SUBACK_PACKET << 4u,
      4,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // return code 1
      1,  // return code 2
  };

  uint16_t packet_id;
  int count;
  lwmqtt_qos_t granted_qos_levels[2];
  lwmqtt_err_t err = lwmqtt_decode_suback(pkt, sizeof(pkt), &packet_id, 2, &count, granted_qos_levels);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(packet_id, 7);
  EXPECT_EQ(count, 2);
  EXPECT_EQ(granted_qos_levels[0], 0);
  EXPECT_EQ(granted_qos_levels[1], 1);
}

TEST(Packet, DecodeSubackError) {
  uint8_t pkt[5] = {
      LWMQTT_SUBACK_PACKET << 4u,
      1,  // <- wrong remaining length
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // return code 1
  };

  uint16_t packet_id;
  int count;
  lwmqtt_qos_t granted_qos_levels[2];
  lwmqtt_err_t err = lwmqtt_decode_suback(pkt, sizeof(pkt), &packet_id, 2, &count, granted_qos_levels);

  EXPECT_EQ(err, LWMQTT_REMAINING_LENGTH_MISMATCH);
}

TEST(Packet, EncodeSubscribe) {
  uint8_t pkt[37] = {
      LWMQTT_SUBSCRIBE_PACKET << 4u | 2,
      35,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // QOS
      0,  // topic name MSB
      8,  // topic name LSB
      '/',
      'a',
      '/',
      'b',
      '/',
      '#',
      '/',
      'c',
      1,   // QOS
      0,   // topic name MSB
      10,  // topic name LSB
      '/',
      'a',
      '/',
      'b',
      '/',
      '#',
      '/',
      'c',
      'd',
      'd',
      2,  // QOS
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_string_t topic_filters[3];
  topic_filters[0] = lwmqtt_string("lwmqtt");
  topic_filters[1] = lwmqtt_string("/a/b/#/c");
  topic_filters[2] = lwmqtt_string("/a/b/#/cdd");

  lwmqtt_qos_t qos_levels[3] = {LWMQTT_QOS0, LWMQTT_QOS1, LWMQTT_QOS2};

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_subscribe(buf, sizeof(pkt), &len, 7, 3, topic_filters, qos_levels);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeSubscribeError) {
  uint8_t buf[2];  // <- too small buffer

  lwmqtt_string_t topic_filters[1];
  topic_filters[0] = lwmqtt_string("lwmqtt");

  lwmqtt_qos_t qos_levels[1] = {LWMQTT_QOS0};

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_subscribe(buf, sizeof(buf), &len, 7, 1, topic_filters, qos_levels);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}

TEST(Packet, EncodeUnsubscribe) {
  uint8_t pkt[34] = {
      LWMQTT_UNSUBSCRIBE_PACKET << 4u | 2,
      32,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // topic name MSB
      6,  // topic name LSB
      'l',
      'w',
      'm',
      'q',
      't',
      't',
      0,  // topic name MSB
      8,  // topic name LSB
      '/',
      'a',
      '/',
      'b',
      '/',
      '#',
      '/',
      'c',
      0,   // topic name MSB
      10,  // topic name LSB
      '/',
      'a',
      '/',
      'b',
      '/',
      '#',
      '/',
      'c',
      'd',
      'd',
  };

  uint8_t buf[sizeof(pkt)];

  lwmqtt_string_t topic_filters[3];
  topic_filters[0] = lwmqtt_string("lwmqtt");
  topic_filters[1] = lwmqtt_string("/a/b/#/c");
  topic_filters[2] = lwmqtt_string("/a/b/#/cdd");

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_unsubscribe(buf, sizeof(pkt), &len, 7, 3, topic_filters);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(Packet, EncodeUnsubscribeError) {
  uint8_t buf[2];  // <- too small buffer

  lwmqtt_string_t topic_filters[1];
  topic_filters[0] = lwmqtt_string("lwmqtt");

  size_t len;
  lwmqtt_err_t err = lwmqtt_encode_unsubscribe(buf, sizeof(buf), &len, 7, 1, topic_filters);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT);
}
