#include <algorithm>
#include <string>
#include <map>
#include "StringHandler.hpp"
#include "SingleFieldValue.hpp"
#include "TwoValueSet.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "Date.hpp"
#include "MapFieldValues.hpp"
#include "ValueWeightArraySet.hpp"
#include "HttpRequest.hpp"
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"
#include "Result.hpp"

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
	std::map<std::string, FieldValueBase*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValueBase*>::iterator itr_now = keyvaluemap.begin();
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
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Post: application/json, application/xml\r\n"
									 "Permission-Policy: geolocation=*, microphone=()\r\n"
									 "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	if (same_class_test_twovalueset(__LINE__, "host", httprequest_test1) == true)
	{
		FieldValueBase *field_values = httprequest_test1.get_field_values(std::string(HOST));
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();

		std::map<std::string, std::string>::const_iterator itr;
		itr = actual_map.find(std::string(URI_HOST));
		EXPECT_EQ("example.com", itr->second);
	}
	// if (same_class_test_twovalueset(__LINE__, "accept-post", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
	// 			"accept-post"));
	// 	compair_twovaluemap( twoval->get_firstvalue(), twoval->get_secondvalue(), "application/json", "application/xml");
	// }
}

TEST(TwoValuseSet, TEST2)
{
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\n"
									 "Accept-Post: application/json, appl,ication/xml\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(TwoValuseSet, TEST3)
{
	const std::string TEST_REQUEST = "GET /example-page HTTP/1.1\r\n"
									 "Permission-Policy: , microphone=()\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}
