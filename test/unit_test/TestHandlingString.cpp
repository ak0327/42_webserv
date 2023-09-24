#include "../../srcs/HandlingString/HandlingString.hpp"
#include "../../srcs/HttpRequest/ValueSet/ValueSet.hpp"
#include "../../srcs/HttpRequest/TwoValueSet/TwoValueSet.hpp"
#include "../../srcs/HttpRequest/RequestLine/RequestLine.hpp"
#include "../../srcs/HttpRequest/ValueArraySet/ValueArraySet.hpp"
#include "../../srcs/HttpRequest/ValueDateSet/ValueDateSet.hpp"
#include "../../srcs/HttpRequest/ValueMap/ValueMap.hpp"
#include "../../srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../../srcs/HttpRequest/HttpRequest.hpp"
#include "../../srcs/HttpRequest/SecurityPolicy/SecurityPolicy.hpp"
#include "gtest/gtest.h"
#include "../../includes/Color.hpp"
#include "../../srcs/Error/Error.hpp"
#include "../../srcs/Debug/Debug.hpp"
#include "Result.hpp"
#include <string>
#include <algorithm>

TEST(HandlingSTring, HandlingStringTEST)
{
	std::string val1 = "   	 aaa bbb ccc      dd ";
	EXPECT_EQ(HandlingString::obtain_withoutows_value(val1), "aaa bbb ccc      dd");

	std::string	val2 = "  \1 thiis is not true line !";
	if (HandlingString::is_printable_content(val2) == true)
		ADD_FAILURE_AT(__FILE__, __LINE__);
}

TEST(HandlingSTring, ALLEMPTY)
{
	const std::string TEST_REQUEST = "a a a\na\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	(void)httprequest_test1;
}

TEST(HandlingSTring, ALLEMPTY_1)
{
	const std::string TEST_REQUEST = "a a a\n\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	(void)httprequest_test1;
}

TEST(HandlingSTring, ALLEMPTY_2)
{
	const std::string TEST_REQUEST = "a a a\n:\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_statuscode(), 400);
}

TEST(HandlingSTring, ALLEMPTY_3)
{
	const std::string TEST_REQUEST = "a a a\n:::\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_statuscode(), 400);
}