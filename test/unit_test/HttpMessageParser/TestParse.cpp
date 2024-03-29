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
	EXPECT_EQ("localhost", result.ok_value());
	EXPECT_EQ(str.length(), end);

	str = "localhost ";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("localhost", result.ok_value());
	EXPECT_EQ(9, end);

	str = "255.255.255.255:8080";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("255.255.255.255", result.ok_value());
	EXPECT_EQ(15, end);

	str = "[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]";
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]", result.ok_value());
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
	EXPECT_EQ("localhost", result.ok_value());
	EXPECT_EQ(10, end);

	str = "[192.168.0.1]";
	//      ^start     ^end
	//     01234567890123456789
	start = 1;
	result = HttpMessageParser::parse_uri_host(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("192.168.0.1", result.ok_value());
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
	EXPECT_EQ("8080", result.ok_value());
	EXPECT_EQ(str.length(), end);

	str = "8080::: ";
	//         ^end
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("8080", result.ok_value());
	EXPECT_EQ(4, end);

	str = "255.255.255.255:8080";
	//        ^end
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("255", result.ok_value());
	EXPECT_EQ(3, end);

	str = "255.255.255.255:8080";
	//                start^   ^endl
	//     01234567890123456789
	start = 16;
	result = HttpMessageParser::parse_port(str, start, &end);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ("8080", result.ok_value());
	EXPECT_EQ(str.length(), end);
}

// parameter = parameter-name "=" parameter-value
TEST(TestHttpMessageParser, ParseParameter) {
	std::string str, name, value;
	std::size_t start, end;
	Result<int, int> result;

	// skip_token
	str = "a=b";
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(str.length(), end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("b", value);
	//--------------------------------------------------------------------------
	str = "a  =  b";
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(str.length(), end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("b", value);
	//--------------------------------------------------------------------------
	str = "a=b;q=1.0";
	//        ^end
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(3, end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("b", value);
	//--------------------------------------------------------------------------
	str = ";a=b;q=1.0";
	//     ^end
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(0, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);
	//--------------------------------------------------------------------------
	str = "";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(0, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);
	//--------------------------------------------------------------------------
	str = "";
	//     012345678
	start = 10;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(start, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);
	//--------------------------------------------------------------------------
	str = "a                    ";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(start, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);
	//--------------------------------------------------------------------------
	str = "a==b";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(start, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);
	//--------------------------------------------------------------------------
	str = "a=b=c";
	//        ^end
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(3, end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("b", value);

	//--------------------------------------------------------------------------
	str = "a=b\"c\"";
	//        ^end
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(3, end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("b", value);
	//--------------------------------------------------------------------------
	str = "a=\"b\"";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_token,
												'=',
												false,
												true);
	EXPECT_FALSE(result.is_ok());
	EXPECT_EQ(start, end);
	EXPECT_EQ("", name);
	EXPECT_EQ("", value);


	////////////////////////////////////////////////////////////////////////////
	// skip_quoted_string

	str = "a=\"b\"";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_quoted_string,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(str.length(), end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("\"b\"", value);
	//--------------------------------------------------------------------------
	str = "a=\"b   c ''\t' \"";
	//     012345678
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_quoted_string,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(str.length(), end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("\"b   c ''\t' \"", value);
	//--------------------------------------------------------------------------
	str = "a=\"b   c ''\t\" \"";
	//                     ^end
	//     01 234567890 1 23456789
	start = 0;
	result = HttpMessageParser::parse_parameter(str,
												start, &end,
												&name, &value,
												HttpMessageParser::skip_token,
												HttpMessageParser::skip_quoted_string,
												'=',
												false,
												true);
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(13, end);
	EXPECT_EQ("a", name);
	EXPECT_EQ("\"b   c ''\t\"", value);
}

TEST(TestHttpMessageParser, ParseParameters) {
	std::string str;
	std::size_t start, end;
	Result<std::map<std::string, std::string>, int> result;
	std::map<std::string, std::string> expected, actual;

	str = ";a=b";
	start = 0;
	result = HttpMessageParser::parse_parameters(str,
												 start, &end,
												 HttpMessageParser::skip_token,
												 HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());

	expected = {{"a", "b"}};
	actual = result.ok_value();
	EXPECT_EQ(expected, actual);
	EXPECT_EQ(str.length(), end);
	//--------------------------------------------------------------------------
	str = ";    a=b";
	start = 0;
	result = HttpMessageParser::parse_parameters(str,
												 start, &end,
												 HttpMessageParser::skip_token,
												 HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());

	expected = {{"a", "b"}};
	actual = result.ok_value();
	EXPECT_EQ(expected, actual);
	EXPECT_EQ(str.length(), end);
	//--------------------------------------------------------------------------
	str = "; a=b;";
	//          ^end
	//     0123456789
	start = 0;
	result = HttpMessageParser::parse_parameters(str,
												 start, &end,
												 HttpMessageParser::skip_token,
												 HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());

	expected = {{"a", "b"}};
	actual = result.ok_value();
	EXPECT_EQ(expected, actual);
	EXPECT_EQ(5, end);

	//--------------------------------------------------------------------------
	str = "; a=b;xxx===";
	//          ^end
	//     0123456789
	start = 0;
	result = HttpMessageParser::parse_parameters(str,
												 start, &end,
												 HttpMessageParser::skip_token,
												 HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());

	expected = {{"a", "b"}};
	actual = result.ok_value();
	EXPECT_EQ(expected, actual);
	EXPECT_EQ(5, end);
	//--------------------------------------------------------------------------
	str = "; a=b ; c=d ;xxx===";
	//                 ^end
	//     01234567890123456789
	start = 0;
	result = HttpMessageParser::parse_parameters(str,
												 start, &end,
												 HttpMessageParser::skip_token,
												 HttpMessageParser::skip_token);
	EXPECT_TRUE(result.is_ok());

	expected = {{"a", "b"}, {"c", "d"}};
	actual = result.ok_value();
	EXPECT_EQ(expected, actual);
	EXPECT_EQ(12, end);
}


TEST(TestHttpMessageParser, SplitStatusCodeAndReasonPhrase) {
    std::string field_value = "200 OK";
    int expected_code, actual_code;
    std::string expected_phrase, actual_phrase;
    ProcResult expected_result, actual_result;

    expected_result = Success;
    expected_code = 200;
    expected_phrase = "OK";
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);
    EXPECT_EQ(expected_code, actual_code);
    EXPECT_EQ(expected_phrase, actual_phrase);

    // -------------------------------------------------------------------------

    field_value = "404 Not Found";

    expected_result = Success;
    expected_code = 404;
    expected_phrase = "Not Found";
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);
    EXPECT_EQ(expected_code, actual_code);
    EXPECT_EQ(expected_phrase, actual_phrase);

    // -------------------------------------------------------------------------

    field_value = "000 status nothing.. but split ok";

    expected_result = Success;
    expected_code = 0;
    expected_phrase = "status nothing.. but split ok";
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);
    EXPECT_EQ(expected_code, actual_code);
    EXPECT_EQ(expected_phrase, actual_phrase);

    // -------------------------------------------------------------------------

    field_value = "999 Not Found";

    expected_result = Success;
    expected_code = 999;
    expected_phrase = "Not Found";
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);
    EXPECT_EQ(expected_code, actual_code);
    EXPECT_EQ(expected_phrase, actual_phrase);


    ////////////////////////////////////////////////////////////////////////////

    field_value = "200";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

    // -------------------------------------------------------------------------

    field_value = "1";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

    // -------------------------------------------------------------------------

    field_value = "1000 ng";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

    // -------------------------------------------------------------------------

    field_value = "200";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

    // -------------------------------------------------------------------------

    field_value = "200 ";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

    // -------------------------------------------------------------------------

    field_value = "";

    expected_result = Failure;
    actual_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                           &actual_code,
                                                                           &actual_phrase);
    EXPECT_EQ(expected_result, actual_result);

}
