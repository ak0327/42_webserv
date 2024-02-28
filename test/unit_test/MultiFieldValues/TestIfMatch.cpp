#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMultiFieldValues, IfMatchOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: \"bfc13a64729c4290ef5b2c2730249c88ca92d82d\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"\"bfc13a64729c4290ef5b2c2730249c88ca92d82d\""};

		EXPECT_EQ(expected_values, actual_values);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMultiFieldValues, IfMatchOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: W/\"67ab43\", \"54ed21\", \"7892dd\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"W/\"67ab43\"", "\"54ed21\"", "\"7892dd\""};

		EXPECT_EQ(expected_values, actual_values);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMultiFieldValues, IfMatchOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: * \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"*"};

		EXPECT_EQ(expected_values, actual_values);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}


TEST(TestMultiFieldValues, IfMatchNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: ,,a \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}


TEST(TestMultiFieldValues, IfMatchNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: *, *, * \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMultiFieldValues, IfMatchNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: \"67ab43 \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMultiFieldValues, IfMatchNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: W\"67ab43\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMultiFieldValues, IfMatchNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Match: W/W/\"67ab43\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_MATCH);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
