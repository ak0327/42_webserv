#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestSetFieldValues, ContentEncodingOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Encoding: gzip\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"gzip"};

		EXPECT_EQ(actual_values.size(), expected_values.size());

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

TEST(TestSetFieldValues, ContentEncodingOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Encoding: gzip,compress, deflate ,br \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"gzip", "compress", "deflate", "br"};

		EXPECT_EQ(actual_values.size(), expected_values.size());

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

TEST(TestSetFieldValues, ContentEncodingOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Encoding: gzip\r\n"
									 "Content-Encoding: GZIP   \r\n"
									 "Content-Encoding: a, b, c, a,a,b,c  , d,123,* \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"a", "b", "c", "a", "a", "b", "c", "d", "123", "*"};

		EXPECT_EQ(actual_values.size(), expected_values.size());

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


TEST(TestSetFieldValues, ContentEncodingNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Encoding: ,,a \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSetFieldValues, ContentEncodingNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Encoding: a,b, \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
