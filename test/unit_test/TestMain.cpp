#include "gtest/gtest.h"
// test関数

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#ifdef __APPLE__

__attribute__((destructor))
static void    destructor(void)
{
    system("leaks -q unit_test");
}

#endif
