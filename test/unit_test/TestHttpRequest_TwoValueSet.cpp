#include "../../srcs/StringHandler/StringHandler.hpp"
#include "../../srcs/HttpRequest/ValueSet/ValueSet.hpp"
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
#include <string>
#include <algorithm>

// GET /example-page HTTP/1.1
// Host: example.com
// Connection: close
// Link: </page1>; rel="next", </page2>; rel="prev"

void	compair_twovaluemap(const std::string &first_target_word, const std::string &second_target_word, const std::string &exp_1, const std::string &exp_2)
{
	EXPECT_EQ(first_target_word, exp_1);
	EXPECT_EQ(second_target_word, exp_2);
}

bool	same_class_test_twovalueset(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず、linkを接尾煮付ける
{
	std::map<std::string, FieldValues*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValues*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
	{
		ADD_FAILURE_AT(__FILE__, line);
		return (false);
	}
	return (true);
}

// GET /example-page HTTP/1.1
// Host: example.com
// Authorization: Digest username="user123",realm="example.com",uri="/example-page",algorithm=MD5,nonce="abcdef123456",response="12345abcde"
// Accept-Post: application/json, application/xml
// Host: example.com
// Permission-Policy: geolocation=*, microphone=()
// Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

TEST(TwoValuseSet, TEST1)
{
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\nHost: example.com\r\nAccept-Post: application/json, application/xml\r\nPermission-Policy: geolocation=*, microphone=()\r\nProxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	if (same_class_test_twovalueset(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Host"));
		compair_twovaluemap( twoval->get_firstvalue(), twoval->get_secondvalue(), "example.com", "");
	}
	if (same_class_test_twovalueset(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Accept-Post"));
		compair_twovaluemap( twoval->get_firstvalue(), twoval->get_secondvalue(), "application/json", "application/xml");
	}
}

TEST(TwoValuseSet, TEST2)
{
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\nAccept-Post: application/json, appl,ication/xml\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(TwoValuseSet, TEST3)
{
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\nPermission-Policy: , microphone=()\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}
