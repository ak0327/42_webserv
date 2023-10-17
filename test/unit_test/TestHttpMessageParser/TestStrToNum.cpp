#include <climits>
#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

TEST(TestStringHandler, ToIntegerNumSuccess) {
	int ret;
	bool succeed;

	ret = HttpMessageParser::to_integer_num("0", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_integer_num("01", &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_integer_num("123", &succeed);
	EXPECT_EQ(123, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_integer_num("2147483647", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_TRUE(succeed);
}

TEST(TestHttpMessageParser, ToIntegerNumFailure) {
	int ret;
	bool succeed;

	ret = HttpMessageParser::to_integer_num("-1", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("  123", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("++0", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("-01", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("+1", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("2147483648", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("+2147483647", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("2147483647000", &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("-21474836480000", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("a", &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	ret = HttpMessageParser::to_integer_num("123a", &succeed);
	EXPECT_EQ(123, ret);
	EXPECT_FALSE(succeed);
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestHttpMessageParser, ToFloatingNumSuccess) {
	double ret;
	bool succeed;

	ret = HttpMessageParser::to_floating_num("0", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0", 1, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0", 2, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0", 3, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("1", 1, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("1.1", 1, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("1.1", 2, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("1.1", 3, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.", 1, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.", 3, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.", 100, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.1234567890", 10, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.1234567890", INT_MAX, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_TRUE(succeed);

	ret = HttpMessageParser::to_floating_num("0.1234567890", UINT_MAX, &succeed);
	EXPECT_EQ(0.1234567890, ret);
	EXPECT_TRUE(succeed);

}

TEST(TestHttpMessageParser, ToFloatingNumFailure) {
	double ret;
	bool succeed;

	// KO, unexpected format: sign
	ret = HttpMessageParser::to_floating_num("-1", 0, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	// KO, precision_digit expected >= 1
	ret = HttpMessageParser::to_floating_num("1.1", 0, &succeed);
	EXPECT_EQ(1.1, ret);
	EXPECT_FALSE(succeed);

	// KO, precision_digit expected >= 2
	ret = HttpMessageParser::to_floating_num("1.12", 1, &succeed);
	EXPECT_EQ(1.12, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: space exist after number
	ret = HttpMessageParser::to_floating_num("1 ", 0, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: space exist after number
	ret = HttpMessageParser::to_floating_num("1 ", 2, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: char exist after number
	ret = HttpMessageParser::to_floating_num("0.123a", 0, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: char exist after number
	ret = HttpMessageParser::to_floating_num("0.123a", 1, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: char exist after number
	ret = HttpMessageParser::to_floating_num("0.123a", 2, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: char exist after number
	ret = HttpMessageParser::to_floating_num("0.123a", 3, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_FALSE(succeed);

	// KO, unexprected format: char exist after number
	ret = HttpMessageParser::to_floating_num("0.123a", 4, &succeed);
	EXPECT_EQ(0.123, ret);
	EXPECT_FALSE(succeed);
}

TEST(TestHttpMessageParser, ToDeltaSeconds) {
	int ret;
	bool succeed;
	std::string str;

	str = "1";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	str = "000001";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	str = "2147483647";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_TRUE(succeed);

	str = "+1";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	str = "2147483648";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_FALSE(succeed);

	str = "21474836488888888888888888888888";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_FALSE(succeed);

	str = " 1";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	str = "1.0";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);

	str = "1a";
	ret = HttpMessageParser::to_delta_seconds(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);
}

TEST(TestHttpMessageParser, ToLongNum) {
	long ret;
	bool succeed;
	std::string str;

	str = "1";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	str = "000001";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_TRUE(succeed);

	str = "2147483647";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(2147483647, ret);
	EXPECT_TRUE(succeed);

	str = "2147483648";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(2147483648, ret);
	EXPECT_TRUE(succeed);

	str = "9223372036854775807";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_TRUE(succeed);

	str = "9223372036854775808";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_FALSE(succeed);

	str = "+1";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	str = "21474836488888888888888888888888";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(LONG_MAX, ret);
	EXPECT_FALSE(succeed);

	str = " 1";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(0, ret);
	EXPECT_FALSE(succeed);

	str = "1.0";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);

	str = "1a";
	ret = HttpMessageParser::to_long_num(str, &succeed);
	EXPECT_EQ(1, ret);
	EXPECT_FALSE(succeed);
}
