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


TEST(TestStringHandler, GetExtension) {
    std::string path, expected, actual;

    path = "/root/a.html";
    expected = "html";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "a.html";
    expected = "html";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "a..html";
    expected = "html";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "root/a.html.b.c.html";
    expected = "html";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "a.a";
    expected = "a";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "a.html.";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "extension_nothing";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "/extension_nothing";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "extension_nothing/";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "/root/a.html/directory/";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = ".gitignore";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "..gitignore";
    expected = "gitignore";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = ".";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = "a.  ng";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = " .   \n\r";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);

    path = ".   \n\r";
    expected = "";
    actual = StringHandler::get_extension(path);
    EXPECT_EQ(expected, actual);
}


TEST(TestStringHandler, Unquote) {
    std::string quoted, actual, expected;

    quoted = "\"abc\"";
    expected = "abc";
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);

    quoted = "\"ab'c\"";
    expected = "ab'c";
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);

    quoted = "\"\"";
    expected = "\"\"";;
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);

    quoted = "\"abc";
    expected = "\"abc";
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);

    quoted = "";
    expected = "";
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);

    quoted = "abc";
    expected = "abc";
    actual = StringHandler::unquote(quoted);
    EXPECT_EQ(expected, actual);
}


TEST(TestHttpMessageParser, Decode) {
    std::string encoded;
    std::string expected, actual;

    encoded = "HelloWorld";
    expected = "HelloWorld";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "Hello%20World";
    expected = "Hello World";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "Hello%20World%21";
    expected = "Hello World!";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "%7E";
    expected = "~";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "Hello%2";
    expected = "Hello%2";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "Hello%2World";
    expected = "Hello%2World";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "";
    expected = "";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "%%";
    expected = "%%";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);

    encoded = "Hello%20%21%22World";
    expected = "Hello !\"World";
    actual = StringHandler::decode(encoded);
    EXPECT_EQ(expected, actual);
}


TEST(TestHttpMessageParser, Normalize) {
    std::string path;
    std::string expected, actual;

    path = "/a/b/c";
    expected = "/a/b/c";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/a/./b/./c";
    expected = "/a/b/c";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/a/b/../c";
    expected = "/a/c";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/a//b/c";
    expected = "/a/b/c";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/../a/b";
    expected = "/a/b";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = ".";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "..";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "...";
    expected = "/...";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = ".././..";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = ".././../";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "../a/b";
    expected = "/a/b";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "//";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "///";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "///./..//";
    expected = "/";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "//a";
    expected = "/a";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/a/b/c/../../d";
    expected = "/a/d";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/a/./b/../../c/../d";
    expected = "/d";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "/../../a";
    expected = "/a";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);

    path = "../../a";
    expected = "/a";
    actual = StringHandler::normalize_to_absolute_path(path);
    EXPECT_EQ(expected, actual);
}
