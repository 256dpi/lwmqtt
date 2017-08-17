#include <gtest/gtest.h>

extern "C" {
#include "../src/helpers.h"
}

TEST(VarNum1, Valid) {
  unsigned char buf[2];
  memset(buf, 0, 2);

  for (int i = 1; i < 128; i++) {
    EXPECT_EQ(1, lwmqtt_varnum_length(i));

    unsigned char *ptr1 = buf;
    int ret = lwmqtt_write_varnum((void **)&ptr1, 1, i);

    unsigned char *ptr2 = buf;
    long num = lwmqtt_read_varnum((void **)&ptr2, 1);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(i, num);
    EXPECT_EQ(0, buf[1]);
    EXPECT_EQ(1, ptr1 - buf);
    EXPECT_EQ(1, ptr2 - buf);
  }
}

TEST(VarNum2, Valid) {
  unsigned char buf[3];
  memset(buf, 0, 3);

  for (int i = 1; i < 128; i++) {
    EXPECT_EQ(2, lwmqtt_varnum_length(128 * i));

    unsigned char *ptr1 = buf;
    int ret = lwmqtt_write_varnum((void **)&ptr1, 2, 128 * i);

    unsigned char *ptr2 = buf;
    long num = lwmqtt_read_varnum((void **)&ptr2, 2);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(128 * i, num);
    EXPECT_EQ(0, buf[2]);
    EXPECT_EQ(2, ptr1 - buf);
    EXPECT_EQ(2, ptr2 - buf);
  }
}

TEST(VarNum3, Valid) {
  unsigned char buf[4];
  memset(buf, 0, 4);

  for (int i = 1; i < 128; i++) {
    EXPECT_EQ(3, lwmqtt_varnum_length(128 * 128 * i));

    unsigned char *ptr1 = buf;
    int ret = lwmqtt_write_varnum((void **)&ptr1, 3, 128 * 128 * i);

    unsigned char *ptr2 = buf;
    long num = lwmqtt_read_varnum((void **)&ptr2, 3);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(128 * 128 * i, num);
    EXPECT_EQ(0, buf[3]);
    EXPECT_EQ(3, ptr1 - buf);
    EXPECT_EQ(3, ptr2 - buf);
  }
}

TEST(VarNum4, Valid) {
  unsigned char buf[5];
  memset(buf, 0, 5);

  for (int i = 1; i < 128; i++) {
    EXPECT_EQ(4, lwmqtt_varnum_length(128 * 128 * 128 * i));

    unsigned char *ptr1 = buf;
    int ret = lwmqtt_write_varnum((void **)&ptr1, 4, 128 * 128 * 128 * i);

    unsigned char *ptr2 = buf;
    long num = lwmqtt_read_varnum((void **)&ptr2, 4);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(128 * 128 * 128 * i, num);
    EXPECT_EQ(0, buf[4]);
    EXPECT_EQ(4, ptr1 - buf);
    EXPECT_EQ(4, ptr2 - buf);
  }
}

TEST(VarNumMax, Valid) {
  unsigned char buf[4] = {0xFF, 0xFF, 0xFF, 0x7F};

  unsigned char *ptr = buf;
  long num = lwmqtt_read_varnum((void **)&ptr, 4);

  EXPECT_EQ(268435455, num);
}
