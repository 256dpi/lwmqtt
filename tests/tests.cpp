#include <gtest/gtest.h>

TEST(SimpleTest, IsEqual) {
  int i = 3;
  EXPECT_EQ(3, i);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
