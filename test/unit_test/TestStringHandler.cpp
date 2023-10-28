#include <climits>
#include "StringHandler.hpp"
#include "gtest/gtest.h"

TEST(TestStringHandler, StoiConvertOK) {
	int ret;
	size_t idx;
	std::string str;
	bool		overflow;

	str = "0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "1";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+2147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+00000002147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483648";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(9, idx);
	EXPECT_EQ(true, overflow);

	str = "21474836470";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "214748364700000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "-2147483648000000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(INT_MIN, ret);
	EXPECT_EQ(11, idx);
	EXPECT_EQ(true, overflow);

	str = " 0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, idx);
	EXPECT_EQ(false, overflow);
}

TEST(TestStringHandler, StoiConvertNG) {
	int ret;
	size_t idx;
	std::string str;
	bool overflow;

	str = " 0 ";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, idx);
	EXPECT_EQ(false, overflow);

	str = "0.0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "++0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, idx);
	EXPECT_EQ(false, overflow);

	str = "0123a";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(123, ret);
	EXPECT_EQ(4, idx);
	EXPECT_EQ(false, overflow);
}


TEST(TestStringHandler, StolConvertOK) {
	long ret;
	size_t idx;
	std::string str;
	bool		overflow;

	str = "0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "1";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "01";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+01";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-01";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483647";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+2147483647";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+00000002147483647";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(INT_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483648";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(2147483648, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "21474836470";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(21474836470, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "214748364700000";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(214748364700000, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-2147483648000000";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(-2147483648000000, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = " 0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "9223372036854775807";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+9223372036854775807";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+00000000000000009223372036854775807";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-00000000000000009223372036854775808";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MIN, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "   -009223372036854775808";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MIN, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "9223372036854775808";  // OF
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_EQ(str.length() - 1, idx);
	EXPECT_EQ(true, overflow);


	str = "   -009223372036854775809";  // OF
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(LONG_MIN, ret);
	EXPECT_EQ(str.length() - 1, idx);
	EXPECT_EQ(true, overflow);
}

TEST(TestStringHandler, StolConvertNG) {
	long ret;
	size_t idx;
	std::string str;
	bool overflow;

	str = " 0 ";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, idx);
	EXPECT_EQ(false, overflow);

	str = "0.0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "++0";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, idx);
	EXPECT_EQ(false, overflow);

	str = "0123a";
	ret = StringHandler::stol(str, &idx, &overflow);
	EXPECT_EQ(123, ret);
	EXPECT_EQ(4, idx);
	EXPECT_EQ(false, overflow);
}
