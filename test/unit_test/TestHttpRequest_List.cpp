#include "StringHandler.hpp"
#include "SingleFieldValue.hpp"
#include "TwoValueSet.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "Date.hpp"
#include "FieldValueMap.hpp"
#include "ValueWeightArraySet.hpp"
#include "HttpRequest.hpp"
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"
#include "Result.hpp"
#include <string>
#include <algorithm>

// GET /example-page HTTP/1.1
// Host: example.com
// Connection: close
// Link: </page1>; rel="next", </page2>; rel="prev"

void	compare_inputvalue_truevalue_linkclass_link(std::map<std::string, std::map<std::string, std::string> > test_map_values, std::map<std::string, std::map<std::string, std::string> > true_map_values, size_t line)
{
	std::map<std::string, std::map<std::string, std::string> >::iterator true_itr_now = true_map_values.begin();
	std::map<std::string, std::string>	checking_map;
	std::map<std::string, std::string>	true_map;
	while (true_itr_now != true_map_values.end())
	{
		if (test_map_values.find(true_itr_now->first) == test_map_values.end())
		{
			std::cout << true_itr_now->first << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, line);
		}
		else
		{
			checking_map = test_map_values[true_itr_now->first];
			true_map = true_map_values[true_itr_now->first];
			std::map<std::string, std::string>::iterator true_map_itr_now = true_map.begin();
			while (true_map_itr_now != true_map.end())
			{
				if (checking_map.find(true_map_itr_now->first) == true_map.end())
				{
					std::cout << true_map_itr_now->first << " is not exist" << std::endl;
					ADD_FAILURE_AT(__FILE__, line);
				}
				else
					EXPECT_EQ(checking_map[true_map_itr_now->first], true_map[true_map_itr_now->first]);
				true_map_itr_now++;
			}
		}
		true_itr_now++;
	}
}

bool	same_class_test_link(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず、linkを接尾煮付ける
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

bool	is_not_exist_link(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず、linkを接尾煮付ける
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
		return (true);
	ADD_FAILURE_AT(__FILE__, line);
	return (false);
}

TEST(List, LIST_TEST)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nLink: </page1>; rel=\"next\", </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	if (same_class_test_link(__LINE__, "link", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:45:00 GMT
		// <https://example.com/style.css>; rel=preload; as=style\r\n
		std::map<std::string, std::map<std::string, std::string> > test_map_values;
		std::map<std::string, std::string>	map_value_1;
		map_value_1["rel"] = "\"next\"";
		std::map<std::string, std::string>	map_value_2;
		map_value_2["rel"] = "\"prev\"";
		test_map_values["</page1>"] = map_value_1;
		test_map_values["</page2>"] = map_value_2;
		LinkClass *linkclass = static_cast<LinkClass*>(httprequest_test1.get_field_values(
				"link"));
		compare_inputvalue_truevalue_linkclass_link(linkclass->get_link_valuemap(), test_map_values, __LINE__);
	}
}

TEST(List, LIST_TEST_ERROR_HEADER)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nL ink: </page1>; rel=\"next\", </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	is_not_exist_link(__LINE__, "link", httprequest_test1);
}

TEST(List, LIST_TEST_ERROR)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nLink: </page1>;;;; rel=\"next\", </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(List, LIST_TEST_ERROR1)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nLink: </page1>; =, </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}
