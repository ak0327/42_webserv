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
		std::set<std::string> values = multi_field_values->get_values();
		std::set<std::string> ans = {"gzip"};

		EXPECT_EQ(true, values.size() == ans.size());

		std::set<std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(*ans_itr, *value_itr);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::set<std::string> values = multi_field_values->get_values();
		std::set<std::string> ans = {"gzip", "compress", "deflate", "br"};

		EXPECT_EQ(true, values.size() == ans.size());

		std::set<std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(*ans_itr, *value_itr);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::set<std::string> values = multi_field_values->get_values();
		std::set<std::string> ans = {"a", "b", "c", "a", "a", "b", "c", "d", "123", "*"};

		EXPECT_EQ(true, values.size() == ans.size());

		std::set<std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(*ans_itr, *value_itr);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
