#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

TEST(TestHttpMessageParser, ParseUriHost) {
	std::string str;
	std::size_t start, end;
	Result<std::string, int> result;

	str = "localhost";
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("localhost", result.get_ok_value());
	EXPECT_EQ(str.length(), end);

	str = "localhost ";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("localhost", result.get_ok_value());
	EXPECT_EQ(9, end);

	str = "255.255.255.255:8080";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("255.255.255.255", result.get_ok_value());
	EXPECT_EQ(15, end);

	str = "[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]", result.get_ok_value());
	EXPECT_EQ(str.length(), end);

	str = "";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_err());
	EXPECT_EQ(0, end);

	str = "[localhost]";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(0, end);

	str = "[localhost]";
	//               ^end
	//     01234567890123456789
	start = 1;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("localhost", result.get_ok_value());
	EXPECT_EQ(10, end);

	str = "[192.168.0.1]";
	//      ^start     ^end
	//     01234567890123456789
	start = 1;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("192.168.0.1", result.get_ok_value());
	EXPECT_EQ(12, end);

	str = "192.168.0.11111";
	//               ^^^^^ng
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(0, end);
}

TEST(TestHttpMessageParser, ParsePort) {
	std::string str;
	std::size_t start, end;
	Result<std::string, int> result;

	str = "8080";
	start = 0;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("8080", result.get_ok_value());
	EXPECT_EQ(str.length(), end);

	str = "8080::: ";
	//         ^end
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("8080", result.get_ok_value());
	EXPECT_EQ(4, end);

	str = "255.255.255.255:8080";
	//        ^end
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("255", result.get_ok_value());
	EXPECT_EQ(3, end);

	str = "255.255.255.255:8080";
	//                start^   ^end
	//     01234567890123456789
	start = 16;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("8080", result.get_ok_value());
	EXPECT_EQ(str.length(), end);
}
