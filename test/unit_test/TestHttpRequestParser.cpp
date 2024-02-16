#include <climits>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "HttpRequest.hpp"
#include "TestHttpRequestParser.hpp"


TEST(HttpRequestParser, GetLine) {
    Result<std::string, std::string> result;
    std::vector<unsigned char> data;
    std::vector<unsigned char>::const_iterator ret;
    std::string expected, actual;
    std::string line;

    expected = "abc";
    line = "abc\r\nd";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    ASSERT_NE(data.end(), ret);
    EXPECT_EQ('d', *ret);


    expected = "abc";
    line = "abc\r\n";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(data.end(), ret);


    expected = "a\rb\nc\n\rd";
    line = "a\rb\nc\n\rd\r\ne";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    ASSERT_NE(data.end(), ret);
    EXPECT_EQ('e', *ret);


    expected = "a\rb\nc\n\rd";
    line = "a\rb\nc\n\rd\r\n\r\ne";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    ASSERT_NE(data.end(), ret);
    EXPECT_EQ(CR, *ret);


    expected = "";
    line = "\r\nabc";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    ASSERT_NE(data.end(), ret);
    EXPECT_EQ('a', *ret);


    expected = "";
    line = "\r\n";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(data.end(), ret);


    expected = "";
    line = "\r\n\r\n";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(CR, *ret);


    expected = "";
    line = "\r\n\n";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(LF, *ret);


    line = "abc\r";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_err());
    EXPECT_EQ(data.end(), ret);


    line = "abc";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_err());
    EXPECT_EQ(data.end(), ret);


    line = "";
    data.assign(line.begin(), line.end());

    result = HttpRequestFriend::get_line(data, data.begin(), &ret);
    ASSERT_TRUE(result.is_err());
    EXPECT_EQ(data.end(), ret);


}
