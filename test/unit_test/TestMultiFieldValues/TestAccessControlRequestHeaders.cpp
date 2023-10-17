#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestSetFieldValues, AccessControlRequestHeadersOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Headers: Content-Type\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCESS_CONTROL_REQUEST_HEADERS);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {std::string(CONTENT_TYPE)};

		EXPECT_EQ(true, actual_values.size() == expected_values.size());

		std::set<std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_values.begin();
		expected_itr = expected_values.begin();
		while (actual_itr != actual_values.end() && expected_itr != expected_values.end()) {
			EXPECT_EQ(*expected_itr, *actual_itr);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_values.end());
		EXPECT_TRUE(expected_itr == expected_values.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSetFieldValues, AccessControlRequestHeadersOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Headers: HosT  , Content-Type \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCESS_CONTROL_REQUEST_HEADERS);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {std::string(HOST), std::string(CONTENT_TYPE)};

		EXPECT_EQ(true, actual_values.size() == expected_values.size());

		std::set<std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_values.begin();
		expected_itr = expected_values.begin();
		while (actual_itr != actual_values.end() && expected_itr != expected_values.end()) {
			EXPECT_EQ(*expected_itr, *actual_itr);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_values.end());
		EXPECT_TRUE(expected_itr == expected_values.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSetFieldValues, AccessControlRequestHeadersOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Headers: gzip\r\n"
									 "Access-Control-Request-Headers: GZIP   \r\n"
									 "Access-Control-Request-Headers: a, b, c \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCESS_CONTROL_REQUEST_HEADERS);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSetFieldValues, AccessControlRequestHeadersNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Headers: Content-Type ,a \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCESS_CONTROL_REQUEST_HEADERS);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSetFieldValues, AccessControlRequestHeadersNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Headers: Content-Type, \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCESS_CONTROL_REQUEST_HEADERS);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
