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
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+2147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+00000002147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483648";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(9, idx);
	EXPECT_EQ(true, overflow);

	str = "21474836470";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "214748364700000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "-2147483648000000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(-2147483648, ret);
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

TEST(TestStringHandler, ToIntegerNumSuccess) {
	int ret;
	bool succeed;

	ret = StringHandler::to_integer_num("0", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_integer_num("01", &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_integer_num("123", &succeed);
	EXPECT_EQ(123, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_integer_num("2147483647", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(true, succeed);
}

TEST(TestStringHandler, ToIntegerNumFailure) {
	int ret;
	bool succeed;

	ret = StringHandler::to_integer_num("-1", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("  123", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("++0", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("-01", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("+1", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("2147483648", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("+2147483647", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("2147483647000", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("-21474836480000", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("a", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	ret = StringHandler::to_integer_num("123a", &succeed);
	EXPECT_EQ(123, ret);
	EXPECT_EQ(false, succeed);
}

TEST(TestStringHandler, ToFloatingNumSuccess) {
	double ret;
	bool succeed;

	ret = StringHandler::to_floating_num("0", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0", 1, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0", 2, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0", 3, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("1", 1, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("1.1", 1, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("1.1", 2, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("1.1", 3, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.", 1, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.", 3, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.", 100, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.1234567890", 10, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.1234567890", INT_MAX, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_EQ(true, succeed);

	ret = StringHandler::to_floating_num("0.1234567890", UINT_MAX, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_EQ(true, succeed);

}

TEST(TestStringHandler, ToFloatingNumFailure) {
	double ret;
	bool succeed;

	// KO, unexpected format: sign
	ret = StringHandler::to_floating_num("-1", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(false, succeed);

	// KO, precision_digit expected >= 1
	ret = StringHandler::to_floating_num("1.1", 0, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_EQ(false, succeed);

	// KO, precision_digit expected >= 2
	ret = StringHandler::to_floating_num("1.12", 1, &succeed);
	EXPECT_EQ(1.12, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: space exist after number
	ret = StringHandler::to_floating_num("1 ", 0, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: space exist after number
	ret = StringHandler::to_floating_num("1 ", 2, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: char exist after number
	ret = StringHandler::to_floating_num("0.123a", 0, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: char exist after number
	ret = StringHandler::to_floating_num("0.123a", 1, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: char exist after number
	ret = StringHandler::to_floating_num("0.123a", 2, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: char exist after number
	ret = StringHandler::to_floating_num("0.123a", 3, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_EQ(false, succeed);

	// KO, unexprected format: char exist after number
	ret = StringHandler::to_floating_num("0.123a", 4, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_EQ(false, succeed);
}
