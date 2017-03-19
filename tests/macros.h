#define EXPECT_ARRAY_EQ(reference, actual, element_count)                 \
  {                                                                       \
    for (int cmp_i = 0; cmp_i < element_count; cmp_i++) {                 \
      EXPECT_EQ(reference[cmp_i], actual[cmp_i]) << "At byte: " << cmp_i; \
    }                                                                     \
  }
