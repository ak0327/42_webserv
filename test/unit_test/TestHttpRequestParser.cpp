#include <climits>
#include <string>
#include <vector>
#include "Color.hpp"
#include "HttpRequest.hpp"
#include "TestHttpRequestParser.hpp"
#include "gtest/gtest.h"


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


TEST(HttpRequestParser, RecvToBuf) {
    std::vector<unsigned char> data_actual, data_expected;
    std::vector<unsigned char>::const_iterator start;
    std::string str, expected_str;


    str = "abcde";
    //       ^st
    data_actual.assign(str.begin(), str.end());
    start = data_actual.begin();
    ++start;
    ++start;

    expected_str = "cde";
    data_expected.assign(expected_str.begin(), expected_str.end());

    HttpRequestFriend::trim(&data_actual, start);
    EXPECT_EQ(data_expected, data_actual);


    str = "abcde";
    //     ^st
    data_actual.assign(str.begin(), str.end());
    start = data_actual.begin();

    expected_str = "abcde";
    data_expected.assign(expected_str.begin(), expected_str.end());

    HttpRequestFriend::trim(&data_actual, start);
    EXPECT_EQ(data_expected, data_actual);


    str = "abcde";
    //         ^st
    data_actual.assign(str.begin(), str.end());
    start = data_actual.end();
    --start;

    expected_str = "e";
    data_expected.assign(expected_str.begin(), expected_str.end());

    HttpRequestFriend::trim(&data_actual, start);
    EXPECT_EQ(data_expected, data_actual);


    str = "abcde";
    //          ^st
    data_actual.assign(str.begin(), str.end());
    start = data_actual.end();

    expected_str = "";
    data_expected.assign(expected_str.begin(), expected_str.end());

    HttpRequestFriend::trim(&data_actual, start);
    EXPECT_EQ(data_expected, data_actual);


    str = "";
    //    ^st
    data_actual.assign(str.begin(), str.end());
    start = data_actual.begin();

    expected_str = "";
    data_expected.assign(expected_str.begin(), expected_str.end());

    HttpRequestFriend::trim(&data_actual, start);
    EXPECT_EQ(data_expected, data_actual);

}


TEST(HttpRequestParser, FindCRLF) {
    std::vector<unsigned char> data;
    std::vector<unsigned char>::const_iterator actual, expected;
    std::string str;

    str = "ab\r\n\r\ncde";
    //       ^
    data.assign(str.begin(), str.end());
    expected = data.begin() + 2;
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(CR, *actual);


    str = "ab\n\rcd\r\ref\r\n";
    //                   ^
    data.assign(str.begin(), str.end());
    expected = data.end() - 2;
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);
    EXPECT_EQ(CR, *actual);


    str = "ab\rcd\n\r\ref\r";
    //                      ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "ab";
    //       ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "";
    //      ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "\r\n";
    //     ^
    data.assign(str.begin(), str.end());
    expected = data.begin();
    HttpRequestFriend::find_crlf(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);
}


TEST(HttpRequestParser, FindEmpty) {
    std::vector<unsigned char> data;
    std::vector<unsigned char>::const_iterator actual, expected;
    std::string str;

    str = "ab\r\n\r\ncde";
    //       ^
    data.assign(str.begin(), str.end());
    expected = data.begin() + 2;
    HttpRequestFriend::find_empty(data, data.begin(), &actual);

    EXPECT_EQ(expected, actual);


    str = "ab\r\ncd\r\n\ref\r\n\r\n";
    //                      ^
    data.assign(str.begin(), str.end());
    expected = data.end() - 4;
    HttpRequestFriend::find_empty(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "ab\r\ncd\r\n\ref\r";
    //                       ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_empty(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "ab";
    //       ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_empty(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "";
    //      ^
    data.assign(str.begin(), str.end());
    expected = data.end();
    HttpRequestFriend::find_empty(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);


    str = "\r\n\r\n";
    //     ^
    data.assign(str.begin(), str.end());
    expected = data.begin();
    HttpRequestFriend::find_empty(data, data.begin(), &actual);
    EXPECT_EQ(expected, actual);
}


// TEST(HttpRequestParser, ) {}
// TEST(HttpRequestParser, ) {}
// TEST(HttpRequestParser, ) {}
