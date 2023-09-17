#include <climits>
#include <string>
#include "gtest/gtest.h"

TEST(Leaks, Leaks) {
	int *arr = new int[10]();

	EXPECT_EQ(0, arr[0]);
	// delete[] arr;
}
