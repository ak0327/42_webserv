#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

TEST(TestHttpMessageParser, GetDoubleColonPos) {
	std::size_t start_pos;
	std::string str;
	Result<std::size_t, int> result;

	str = "::";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(0, result.ok_value());

	str = ":::";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(0, result.ok_value());

	str = "xxxxxxxxxx::xxxxxx";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(10, result.ok_value());

	str = "xxxxxxxxxx::";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(10, result.ok_value());

	str = "x::x::x";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(1, result.ok_value());

	str = "xxxxxxxxxx:xxxxxx";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());

	str = "xxxxxxxxxx:";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());

	str = "";
	//     012345678901234567890
	start_pos = 0;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());

	str = "";
	//     012345678901234567890
	start_pos = 10;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());

	str = "\0\0\0";
	//     012345678901234567890
	start_pos = 1;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());

	str = "\0xxx::yyy";
	//     012345678901234567890
	start_pos = 3;
	result = HttpMessageParser::get_double_colon_pos(str, start_pos);
	EXPECT_FALSE(result.is_ok());
}
