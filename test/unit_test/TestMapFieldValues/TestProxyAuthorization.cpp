#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, ProxyAuthorizationOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Proxy-Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(PROXY_AUTHORIZATION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(AUTH_SCHEME), "Basic"},
												  {std::string(AUTH_PARAM), "YWxhZGRpbjpvcGVuc2VzYW1l"}};

		EXPECT_EQ(actual_map.size(), expected_map.size());

		std::map<std::string, std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_map.begin();
		expected_itr = expected_map.begin();
		while (actual_itr != actual_map.end() && expected_itr != expected_map.end()) {
			EXPECT_EQ(expected_itr->second, actual_itr->second);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_map.end());
		EXPECT_TRUE(expected_itr == expected_map.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, ProxyAuthorizationOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Proxy-Authorization: basic\r\n"
									 "proxy-authorization: a\r\n"
									 "Proxy-Authorization: Basic\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(PROXY_AUTHORIZATION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(AUTH_SCHEME), "Basic"}};

		EXPECT_EQ(actual_map.size(), expected_map.size());

		std::map<std::string, std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_map.begin();
		expected_itr = expected_map.begin();
		while (actual_itr != actual_map.end() && expected_itr != expected_map.end()) {
			EXPECT_EQ(expected_itr->second, actual_itr->second);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_map.end());
		EXPECT_TRUE(expected_itr == expected_map.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


////////////////////////////////////////////////////////////////////////////////

TEST(TestMapFieldValues, ProxyAuthorizationNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Proxy-Authorization: Basic    YWxhZGRpbjpvcGVuc2VzYW1l \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(PROXY_AUTHORIZATION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, ProxyAuthorizationNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Proxy-Authorization: Basic aaa==hoge\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(PROXY_AUTHORIZATION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
