#include <algorithm>
#include <string>
#include "StringHandler.hpp"
#include "SingleFieldValue.hpp"
#include "TwoValueSet.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "Date.hpp"
#include "MapFieldValues.hpp"
#include "MapSetFieldValues.hpp"
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
typedef std::set<std::map<std::string, std::string> > map_set;

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

bool	is_not_exist_link(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず、linkを接尾煮付ける
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
		return (true);
	ADD_FAILURE_AT(__FILE__, line);
	return (false);
}

TEST(List, LIST_TEST)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Host: example\r\n"
									 "Link: </page1>; rel=\"next\", </page2>; rel=\"prev\"\r\n"
									 "\r\n";
	HttpRequest request(TEST_REQUEST);


	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {
				{
						{std::string(URI_REFERENCE), "/page1"},
						{"rel", "\"next\""},
				}, {
						{std::string(URI_REFERENCE), "/page2"},
						{"rel", "\"prev\""},
				}};

		EXPECT_EQ(actual_map_set.size(), expected_map_set.size());

		map_set::const_iterator actual_map_set_itr = actual_map_set.begin();
		map_set::const_iterator expected_map_set_itr = expected_map_set.begin();

		while (actual_map_set_itr != actual_map_set.end() && expected_map_set_itr != expected_map_set.end()) {
			std::map<std::string, std::string> actual_map = *actual_map_set_itr;
			std::map<std::string, std::string> expected_map = *expected_map_set_itr;;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			std::map<std::string, std::string>::const_iterator actual_map_itr = actual_map.begin();
			std::map<std::string, std::string>::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			++actual_map_set_itr;
			++expected_map_set_itr;
		}
		EXPECT_TRUE(actual_map_set_itr == actual_map_set.end());
		EXPECT_TRUE(expected_map_set_itr == expected_map_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(List, LIST_TEST_ERROR_HEADER)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "L ink: </page1>; rel=\"next\", </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	is_not_exist_link(__LINE__, "link", httprequest_test1);
}

TEST(List, LIST_TEST_ERROR)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Link: </page1>;;;; rel=\"next\", </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(List, LIST_TEST_ERROR1)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Link: </page1>; =, </page2>; rel=\"prev\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}
