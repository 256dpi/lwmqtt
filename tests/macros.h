#define EXPECT_ARRAY_EQ(TYPE, reference, actual, element_count)             \
  {                                                                         \
    TYPE* reference_ = static_cast<TYPE*>(reference);                       \
    TYPE* actual_ = static_cast<TYPE*>(actual);                             \
    for (int cmp_i = 0; cmp_i < element_count; cmp_i++) {                   \
      EXPECT_EQ(reference_[cmp_i], actual_[cmp_i]) << "At byte: " << cmp_i; \
    }                                                                       \
  }
