#include <gtest/gtest.h>

extern "C" {
#include "../src/client.h"
#include "../src/string.h"
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

TEST(PublishTest, DecodeError1) {
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

/*
func TestPublishPacketDecode1(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH<<4) | 11,
                23,
                0, // topic name MSB
                7, // topic name LSB
                's', 'u', 'r', 'g', 'e', 'm', 'q',
                0, // packet ID MSB
                7, // packet ID LSB
                's', 'e', 'n', 'd', ' ', 'm', 'e', ' ', 'h', 'o', 'm', 'e',
        }

        pkt := NewPublishPacket()
        n, err := pkt.Decode(pktBytes)

        assert.NoError(t, err)
        assert.Equal(t, len(pktBytes), n)
        assert.Equal(t, uint16(7), pkt.PacketID)
        assert.Equal(t, "surgemq", pkt.Message.Topic)
        assert.Equal(t, []byte("send me home"), pkt.Message.Payload)
        assert.Equal(t, uint8(1), pkt.Message.QOS)
        assert.Equal(t, true, pkt.Message.Retain)
        assert.Equal(t, true, pkt.Dup)
}

func TestPublishPacketDecode2(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH << 4),
                21,
                0, // topic name MSB
                7, // topic name LSB
                's', 'u', 'r', 'g', 'e', 'm', 'q',
                's', 'e', 'n', 'd', ' ', 'm', 'e', ' ', 'h', 'o', 'm', 'e',
        }

        pkt := NewPublishPacket()
        n, err := pkt.Decode(pktBytes)

        assert.NoError(t, err)
        assert.Equal(t, len(pktBytes), n)
        assert.Equal(t, uint16(0), pkt.PacketID)
        assert.Equal(t, "surgemq", pkt.Message.Topic)
        assert.Equal(t, []byte("send me home"), pkt.Message.Payload)
        assert.Equal(t, uint8(0), pkt.Message.QOS)
        assert.Equal(t, false, pkt.Message.Retain)
        assert.Equal(t, false, pkt.Dup)
}

func TestPublishPacketDecodeError1(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH << 4),
                2, // <- too much
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}

func TestPublishPacketDecodeError2(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH<<4) | 6, // <- wrong qos
                0,
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}

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
}

func TestPublishPacketDecodeError6(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH<<4) | 2,
                2,
                0, // topic name MSB
                1, // topic name LSB
                't',
                0,
                0, // <- zero packet id
        }

        pkt := NewPublishPacket()
        _, err := pkt.Decode(pktBytes)

        assert.Error(t, err)
}

func TestPublishPacketEncode1(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH<<4) | 11,
                23,
                0, // topic name MSB
                7, // topic name LSB
                's', 'u', 'r', 'g', 'e', 'm', 'q',
                0, // packet ID MSB
                7, // packet ID LSB
                's', 'e', 'n', 'd', ' ', 'm', 'e', ' ', 'h', 'o', 'm', 'e',
        }

        pkt := NewPublishPacket()
        pkt.Message.Topic = "surgemq"
        pkt.Message.QOS = QOSAtLeastOnce
        pkt.Message.Retain = true
        pkt.Dup = true
        pkt.PacketID = 7
        pkt.Message.Payload = []byte("send me home")

        dst := make([]byte, pkt.Len())
        n, err := pkt.Encode(dst)

        assert.NoError(t, err)
        assert.Equal(t, len(pktBytes), n)
        assert.Equal(t, pktBytes, dst[:n])
}

func TestPublishPacketEncode2(t *testing.T) {
        pktBytes := []byte{
                byte(PUBLISH << 4),
                21,
                0, // topic name MSB
                7, // topic name LSB
                's', 'u', 'r', 'g', 'e', 'm', 'q',
                's', 'e', 'n', 'd', ' ', 'm', 'e', ' ', 'h', 'o', 'm', 'e',
        }

        pkt := NewPublishPacket()
        pkt.Message.Topic = "surgemq"
        pkt.Message.Payload = []byte("send me home")

        dst := make([]byte, pkt.Len())
        n, err := pkt.Encode(dst)

        assert.NoError(t, err)
        assert.Equal(t, len(pktBytes), n)
        assert.Equal(t, pktBytes, dst[:n])
}

func TestPublishPacketEncodeError1(t *testing.T) {
        pkt := NewPublishPacket()
        pkt.Message.Topic = "" // <- empty topic

        dst := make([]byte, pkt.Len())
        _, err := pkt.Encode(dst)

        assert.Error(t, err)
}

func TestPublishPacketEncodeError2(t *testing.T) {
        pkt := NewPublishPacket()
        pkt.Message.Topic = "t"
        pkt.Message.QOS = 3 // <- wrong qos

        dst := make([]byte, pkt.Len())
        _, err := pkt.Encode(dst)

        assert.Error(t, err)
}

func TestPublishPacketEncodeError3(t *testing.T) {
        pkt := NewPublishPacket()
        pkt.Message.Topic = "t"

        dst := make([]byte, 1) // <- too small
        _, err := pkt.Encode(dst)

        assert.Error(t, err)
}

func TestPublishPacketEncodeError4(t *testing.T) {
        pkt := NewPublishPacket()
        pkt.Message.Topic = string(make([]byte, 65536)) // <- too big

        dst := make([]byte, pkt.Len())
        _, err := pkt.Encode(dst)

        assert.Error(t, err)
}

func TestPublishPacketEncodeError5(t *testing.T) {
        pkt := NewPublishPacket()
        pkt.Message.Topic = "test"
        pkt.Message.QOS = 1
        pkt.PacketID = 0 // <- zero packet id

        dst := make([]byte, pkt.Len())
        _, err := pkt.Encode(dst)

        assert.Error(t, err)
}
 */
