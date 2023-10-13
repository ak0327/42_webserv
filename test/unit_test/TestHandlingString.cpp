#include <string>
#include <algorithm>
#include "../../srcs/StringHandler/StringHandler.hpp"
#include "SingleFieldValue.hpp"
#include "../../srcs/HttpRequest/TwoValueSet/TwoValueSet.hpp"
#include "../../srcs/HttpRequest/RequestLine/RequestLine.hpp"
#include "../../srcs/HttpRequest/ValueArraySet/ValueArraySet.hpp"
#include "Date.hpp"
#include "../../srcs/HttpRequest/ValueMap/ValueMap.hpp"
#include "../../srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../../srcs/HttpRequest/HttpRequest.hpp"
#include "gtest/gtest.h"
#include "../../includes/Color.hpp"
#include "../../srcs/Error/Error.hpp"
#include "../../srcs/Debug/Debug.hpp"
#include "Result.hpp"
#include "HttpMessageParser.hpp"

TEST(HandlingString, IS_END_WITH_CR)
{
	const std::string TEST_REQUEST = "";
    if (HttpMessageParser::is_end_with_cr(TEST_REQUEST) == true)
		ADD_FAILURE_AT(__FILE__, __LINE__);
}

TEST(HandlingString, HandlingStringTEST)
{
	std::string val1 = "   	 aaa bbb ccc      dd ";
	EXPECT_EQ(StringHandler::obtain_withoutows_value(val1), "aaa bbb ccc      dd");

	std::string	val2 = "  \1 thiis is not true line !";
	if (HttpMessageParser::is_printable(val2) == true)
		ADD_FAILURE_AT(__FILE__, __LINE__);
}

TEST(HandlingString, ALLEMPTY)
{
	const std::string TEST_REQUEST = "a a a\na\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	(void)httprequest_test1;
}

TEST(HandlingString, ALLEMPTY_1)
{
	const std::string TEST_REQUEST = "a a a\n\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	(void)httprequest_test1;
}

TEST(HandlingString, ALLEMPTY_2)
{
	const std::string TEST_REQUEST = "a a a\n:\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(HandlingString, ALLEMPTY_3)
{
	const std::string TEST_REQUEST = "a a a\n:::\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(HandlingString, IS_QUOTED)
{
    if (StringHandler::is_quoted("") == true)
		ADD_FAILURE_AT(__FILE__, __LINE__);
	if (StringHandler::is_quoted("\"\"") == false)
		ADD_FAILURE_AT(__FILE__, __LINE__);
	EXPECT_EQ(false, StringHandler::is_quoted("\""));
}

TEST(HandlingString, IS_SEMICORON_TRUE)
{
	EXPECT_EQ(true, StringHandler::is_endl_semicolon_and_no_inner_semicoron("\";"));
	EXPECT_EQ(true, StringHandler::is_endl_semicolon_and_no_inner_semicoron(";"));
	EXPECT_EQ(true, StringHandler::is_endl_semicolon_and_no_inner_semicoron("               ;"));
	EXPECT_EQ(true, StringHandler::is_endl_semicolon_and_no_inner_semicoron(";"));
}

TEST(HandlingString, IS_SEMICORON_FALSE)
{
	EXPECT_EQ(false, StringHandler::is_endl_semicolon_and_no_inner_semicoron(";;;;;;;;;;;;;;;;"));
	EXPECT_EQ(false, StringHandler::is_endl_semicolon_and_no_inner_semicoron("; ; ; ; ; ; ; "));
	EXPECT_EQ(false, StringHandler::is_endl_semicolon_and_no_inner_semicoron("aaaa ; "));
	EXPECT_EQ(false, StringHandler::is_endl_semicolon_and_no_inner_semicoron(""));
	EXPECT_EQ(false, StringHandler::is_endl_semicolon_and_no_inner_semicoron(";             ;"));
}

TEST(HandlingString, is_positive_under_intmax_double_TRUE)
{
    EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.0"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("1.0"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.1"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.2"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.3"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.001"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.0000000001"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("00000000000000.0000000000000"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0.00000001234567890"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("1.2"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double(".0"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double(".123"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("2147483647.0"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("1.01"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0000000000.1"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("0000000000.10000000000"));
	EXPECT_EQ(true, StringHandler::is_positive_under_intmax_double("00000000000000000000000000000.10000000000"));
}

TEST(HandlingString, is_positive_under_intmax_double_FALSE)
{
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("................................"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("2 1 4 7 4 8 3 6 4 9 . 0 "));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("0.0d"));//数値以外許可しないため問題なし
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("-2147483649.0"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("-2.0"));
    EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("0."));// true
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("0.."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("+0.1"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("-0.1"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("0.."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("0.."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(".0.."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(".0aaa"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("aaa"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("aaa."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(".aaa"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(""));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(".."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double(".a"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("a."));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("1797693134862315708145274237317043567980705675258449965989174768031572607800285387605895586327668781715404589535143824642343213268894641827684675467035375169860499105765512820762454900903893289440758685084551339423045832369032229481658085593321233482747978262041447231687381771809192998812504040261841248583689999999999999999999.0"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("17976931348623157081452742373170435679807056752584499659891747680315726078002853876058955863276687817154045895351438246423432132688946418276846754670353751698604991057655128207624549009038932894407586850845513394230458323690322294816580855933212334827479782620414472316873817718091929988125040402618412485836.0"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.0"));
	EXPECT_EQ(false, StringHandler::is_positive_under_intmax_double("2147483648.0"));//false
}

TEST(HandlingString, IS_POSITIVE_AND_UNDER_INTMAX_TRUE)
{
    EXPECT_EQ(true, StringHandler::is_positive_and_under_intmax("2147483647"));
	EXPECT_EQ(true, StringHandler::is_positive_and_under_intmax("0000000000000000"));
	EXPECT_EQ(true, StringHandler::is_positive_and_under_intmax("0000000000000001"));
}

TEST(HandlingString, IS_POSITIVE_AND_UNDER_INTMAX_FALSE)
{
	EXPECT_EQ(false, StringHandler::is_positive_and_under_intmax("aaa"));
	EXPECT_EQ(false, StringHandler::is_positive_and_under_intmax("2147483648"));
	EXPECT_EQ(false, StringHandler::is_positive_and_under_intmax("9223372036854775807"));
	EXPECT_EQ(false, StringHandler::is_positive_and_under_intmax("-2147483647"));
	EXPECT_EQ(false, StringHandler::is_positive_and_under_intmax(" 7"));
}
