#include <gtest/gtest.h>

extern "C" {
#include "../src/client.h"
}

#include "macros.h"

TEST(ConnectTest, Encode1) {
  unsigned char pkt[62] = {
      LWMQTT_CONNECT_PACKET << 4,
      60,
      0,  // Protocol String MSB
      4,  // Protocol String LSB
      'M',
      'Q',
      'T',
      'T',
      4,    // Protocol level 4
      204,  // Connect Flags
      0,    // Keep Alive MSB
      10,   // Keep Alive LSB
      0,    // Client ID MSB
      7,    // Client ID LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
      0,  // Will Topic MSB
      4,  // Will Topic LSB
      'w',
      'i',
      'l',
      'l',
      0,   // Will Message MSB
      12,  // Will Message LSB
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
      0,  // Username ID MSB
      7,  // Username ID LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
      0,   // Password ID MSB
      10,  // Password ID LSB
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

  unsigned char buf[62];

  lwmqtt_will_t will = lwmqtt_default_will;
  will.topic.c_string = (char*)"will";
  will.payload = (void*)"send me home";
  will.payload_len = (int)strlen((const char*)will.payload);
  will.qos = LWMQTT_QOS1;

  lwmqtt_options_t opts = lwmqtt_default_options;
  opts.clean_session = false;
  opts.keep_alive = 10;
  opts.client_id.c_string = (char*)"surgemq";
  opts.username.c_string = (char*)"surgemq";
  opts.password.c_string = (char*)"verysecret";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, 62, &len, &opts, &will);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(ConnectTest, Encode2) {
  unsigned char pkt[14] = {
      LWMQTT_CONNECT_PACKET << 4,
      12,
      0,  // Protocol String MSB
      4,  // Protocol String LSB
      'M',
      'Q',
      'T',
      'T',
      4,   // Protocol level 4
      2,   // Connect Flags
      0,   // Keep Alive MSB
      60,  // Keep Alive LSB
      0,   // Client ID MSB
      0,   // Client ID LSB
  };

  unsigned char buf[14];

  lwmqtt_options_t opts = lwmqtt_default_options;

  int len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, 14, &len, &opts, NULL);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(ConnectTest, EncodeError1) {
  unsigned char buf[4];  // <- too small buffer

  lwmqtt_options_t opts = lwmqtt_default_options;

  int len;
  lwmqtt_err_t err = lwmqtt_encode_connect(buf, 4, &len, &opts, NULL);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}

TEST(ConnackTest, Decode1) {
  unsigned char pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4, 2,
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t err = lwmqtt_decode_connack(&session_present, &connack, pkt, 4);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(session_present, 0);
  EXPECT_EQ(connack, 0);
}

TEST(ConnackTest, DecodeError1) {
  unsigned char pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4,
      3,  // <-- wrong size
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t err = lwmqtt_decode_connack(&session_present, &connack, pkt, 4);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

TEST(ConnackTest, DecodeError2) {
  unsigned char pkt[3] = {
      LWMQTT_CONNACK_PACKET << 4, 3,
      0,  // session not present
          // <- missing packet size
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t err = lwmqtt_decode_connack(&session_present, &connack, pkt, 3);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

TEST(ZeroTest, Encode1) {
  unsigned char pkt[2] = {LWMQTT_PINGREQ_PACKET << 4, 0};

  unsigned char buf[2];

  int len;
  lwmqtt_err_t err = lwmqtt_encode_zero(buf, 2, &len, LWMQTT_PINGREQ_PACKET);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(AckTest, Decode1) {
  unsigned char pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4, 2,
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  lwmqtt_packet_t type;
  bool dup;
  unsigned short packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(&type, &dup, &packet_id, pkt, 4);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(type, LWMQTT_PUBACK_PACKET);
  EXPECT_EQ(dup, false);
  EXPECT_EQ(packet_id, 7);
}

TEST(AckTest, DecodeError1) {
  unsigned char pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4,
      1,  // <-- wrong remaining length
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  lwmqtt_packet_t type;
  bool dup;
  unsigned short packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(&type, &dup, &packet_id, pkt, 4);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

TEST(AckTest, DecodeError2) {
  unsigned char pkt[3] = {
      LWMQTT_PUBACK_PACKET << 4,
      1,  // <-- wrong remaining length
      0,  // packet ID MSB
          //  <- insufficient bytes
  };

  lwmqtt_packet_t type;
  bool dup;
  unsigned short packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(&type, &dup, &packet_id, pkt, 4);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

TEST(AckTest, Encode1) {
  unsigned char pkt[4] = {
      LWMQTT_PUBACK_PACKET << 4, 2,
      0,  // packet ID MSB
      7,  // packet ID LSB
  };

  unsigned char buf[4];

  int len;
  lwmqtt_err_t err = lwmqtt_encode_ack(buf, 4, &len, LWMQTT_PUBACK_PACKET, 0, 7);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(AckTest, EncodeError1) {
  unsigned char buf[2];  // <- too small buffer

  int len;
  lwmqtt_err_t err = lwmqtt_encode_ack(buf, 2, &len, LWMQTT_PUBACK_PACKET, 0, 7);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}

TEST(PublishTest, Decode1) {
  unsigned char pkt[25] = {
      LWMQTT_PUBLISH_PACKET << 4 | 11,
      23,
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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
  lwmqtt_qos_t qos;
  bool retained;
  unsigned short packet_id;
  lwmqtt_string_t topic;
  unsigned char* payload;
  int payload_len;
  lwmqtt_err_t err = lwmqtt_decode_publish(&dup, &qos, &retained, &packet_id, &topic, &payload, &payload_len, pkt, 25);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(dup, true);
  EXPECT_EQ(qos, 1);
  EXPECT_EQ(retained, true);
  EXPECT_EQ(packet_id, 7);
  EXPECT_ARRAY_EQ("surgemq", topic.lp_string.data, 7);
  EXPECT_ARRAY_EQ("send me home", payload, 12);
}

TEST(PublishTest, Decode2) {
  unsigned char pkt[23] = {
      LWMQTT_PUBLISH_PACKET << 4,
      21,
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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
  lwmqtt_qos_t qos;
  bool retained;
  unsigned short packet_id;
  lwmqtt_string_t topic;
  unsigned char* payload;
  int payload_len;
  lwmqtt_err_t err = lwmqtt_decode_publish(&dup, &qos, &retained, &packet_id, &topic, &payload, &payload_len, pkt, 23);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(dup, false);
  EXPECT_EQ(qos, 0);
  EXPECT_EQ(retained, false);
  EXPECT_EQ(packet_id, 0);
  EXPECT_ARRAY_EQ("surgemq", topic.lp_string.data, 7);
  EXPECT_ARRAY_EQ("send me home", payload, 12);
}

TEST(PublishTest, DecodeError1) {
  unsigned char pkt[2] = {
      LWMQTT_PUBLISH_PACKET << 4,
      2,  // <-- too much
  };

  bool dup;
  lwmqtt_qos_t qos;
  bool retained;
  unsigned short packet_id;
  lwmqtt_string_t topic;
  unsigned char* payload;
  int payload_len;
  lwmqtt_err_t err = lwmqtt_decode_publish(&dup, &qos, &retained, &packet_id, &topic, &payload, &payload_len, pkt, 2);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

/*
func TestPublishPacketDecodeError3(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH << 4),
                0,
                // <- missing topic stuff
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}

func TestPublishPacketDecodeError4(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH << 4),
                2,
                0, // topic name MSB
                1, // topic name LSB
                // <- missing topic string
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}

func TestPublishPacketDecodeError5(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH<<4) | 2,
                2,
                0, // topic name MSB
                1, // topic name LSB
                't',
                // <- missing packet id
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}*/

TEST(PublishTest, Encode1) {
  unsigned char pkt[25] = {
      LWMQTT_PUBLISH_PACKET << 4 | 11,
      23,
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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

  unsigned char buf[25];

  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char*)"surgemq";

  unsigned char* payload = (unsigned char*)"send me home";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, 25, &len, true, LWMQTT_QOS1, true, 7, topic, payload, 12);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(PublishTest, Encode2) {
  unsigned char pkt[23] = {
      LWMQTT_PUBLISH_PACKET << 4,
      21,
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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

  unsigned char buf[23];

  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char*)"surgemq";
  unsigned char* payload = (unsigned char*)"send me home";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, 23, &len, false, LWMQTT_QOS0, false, 0, topic, payload, 12);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(PublishTest, EncodeError1) {
  unsigned char buf[2];  // <- too small buffer

  lwmqtt_string_t topic = lwmqtt_default_string;
  topic.c_string = (char*)"surgemq";
  unsigned char* payload = (unsigned char*)"send me home";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_publish(buf, 2, &len, false, LWMQTT_QOS0, false, 0, topic, payload, 12);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}

TEST(SubackTest, Decode1) {
  unsigned char pkt[8] = {
      LWMQTT_SUBACK_PACKET << 4,
      4,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // return code 1
      1,  // return code 2
  };

  unsigned short packet_id;
  int count;
  lwmqtt_qos_t granted_qos_levels[2];
  lwmqtt_err_t err = lwmqtt_decode_suback(&packet_id, 2, &count, granted_qos_levels, pkt, 8);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_EQ(packet_id, 7);
  EXPECT_EQ(count, 2);
  EXPECT_EQ(granted_qos_levels[0], 0);
  EXPECT_EQ(granted_qos_levels[1], 1);
}

TEST(SubackTest, DecodeError1) {
  unsigned char pkt[5] = {
      LWMQTT_SUBACK_PACKET << 4,
      1,  // <- wrong remaining length
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // return code 1
  };

  lwmqtt_packet_t type;
  bool dup;
  unsigned short packet_id;
  lwmqtt_err_t err = lwmqtt_decode_ack(&type, &dup, &packet_id, pkt, 5);

  EXPECT_EQ(err, LWMQTT_LENGTH_MISMATCH);
}

TEST(SubscribeTest, Encode1) {
  unsigned char pkt[38] = {
      LWMQTT_SUBSCRIBE_PACKET << 4 | 2,
      36,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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

  unsigned char buf[38];

  lwmqtt_string_t topic_filters[3] = {lwmqtt_default_string, lwmqtt_default_string, lwmqtt_default_string};
  topic_filters[0].c_string = (char*)"surgemq";
  topic_filters[1].c_string = (char*)"/a/b/#/c";
  topic_filters[2].c_string = (char*)"/a/b/#/cdd";

  lwmqtt_qos_t qos_levels[3] = {LWMQTT_QOS0, LWMQTT_QOS1, LWMQTT_QOS2};

  int len;
  lwmqtt_err_t err = lwmqtt_encode_subscribe(buf, 38, &len, 7, 3, topic_filters, qos_levels);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(SubscribeTest, EncodeError1) {
  unsigned char buf[2];  // <- too small buffer

  lwmqtt_string_t topic_filters[1] = {lwmqtt_default_string};
  topic_filters[0].c_string = (char*)"surgemq";

  lwmqtt_qos_t qos_levels[1] = {LWMQTT_QOS0};

  int len;
  lwmqtt_err_t err = lwmqtt_encode_subscribe(buf, 2, &len, 7, 1, topic_filters, qos_levels);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}

TEST(UnsubscribeTest, Encode1) {
  unsigned char pkt[35] = {
      LWMQTT_UNSUBSCRIBE_PACKET << 4 | 2,
      33,
      0,  // packet ID MSB
      7,  // packet ID LSB
      0,  // topic name MSB
      7,  // topic name LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
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

  unsigned char buf[38];

  lwmqtt_string_t topic_filters[3] = {lwmqtt_default_string, lwmqtt_default_string, lwmqtt_default_string};
  topic_filters[0].c_string = (char*)"surgemq";
  topic_filters[1].c_string = (char*)"/a/b/#/c";
  topic_filters[2].c_string = (char*)"/a/b/#/cdd";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_unsubscribe(buf, 38, &len, 7, 3, topic_filters);

  EXPECT_EQ(err, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(pkt, buf, len);
}

TEST(UnsubscribeTest, EncodeError1) {
  unsigned char buf[2];  // <- too small buffer

  lwmqtt_string_t topic_filters[1] = {lwmqtt_default_string};
  topic_filters[0].c_string = (char*)"surgemq";

  int len;
  lwmqtt_err_t err = lwmqtt_encode_unsubscribe(buf, 2, &len, 7, 1, topic_filters);

  EXPECT_EQ(err, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}
