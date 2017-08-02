#include <gtest/gtest.h>

extern "C" {
#include "../src/helpers.h"
}

TEST(VarNum1, Valid) {
  unsigned char buf[5];
  memset(buf, 0, 5);

  unsigned char* ptr1 = buf;
  lwmqtt_write_varnum((void**)&ptr1, 1);

  unsigned char* ptr2 = buf;
  int num = lwmqtt_read_varnum((void**)&ptr2);

  EXPECT_EQ(1, num);
  EXPECT_EQ(0, buf[4]);
  EXPECT_EQ(1, ptr1 - buf);
  EXPECT_EQ(1, ptr2 - buf);
}

TEST(VarNum1K, Valid) {
  unsigned char buf[5];
  memset(buf, 0, 5);

  unsigned char* ptr1 = buf;
  lwmqtt_write_varnum((void**)&ptr1, 1000);

  unsigned char* ptr2 = buf;
  int num = lwmqtt_read_varnum((void**)&ptr2);

  EXPECT_EQ(1000, num);
  EXPECT_EQ(0, buf[4]);
  EXPECT_EQ(2, ptr1 - buf);
  EXPECT_EQ(2, ptr2 - buf);
}

TEST(VarNum1M, Valid) {
  unsigned char buf[5];
  memset(buf, 0, 5);

  unsigned char* ptr1 = buf;
  lwmqtt_write_varnum((void**)&ptr1, 1000000);

  unsigned char* ptr2 = buf;
  int num = lwmqtt_read_varnum((void**)&ptr2);

  EXPECT_EQ(1000000, num);
  EXPECT_EQ(0, buf[4]);
  EXPECT_EQ(3, ptr1 - buf);
  EXPECT_EQ(3, ptr2 - buf);
}

TEST(VarNumOverflow, Valid) {
  unsigned char buf[5];
  memset(buf, 0, 5);

  unsigned char* ptr1 = buf;
  lwmqtt_write_varnum((void**)&ptr1, 1000000000);

  unsigned char* ptr2 = buf;
  int num = lwmqtt_read_varnum((void**)&ptr2);

  EXPECT_EQ(-1, num);
  EXPECT_EQ(0, buf[4]);
  EXPECT_EQ(4, ptr1 - buf);
  EXPECT_EQ(0, ptr2 - buf);
}
