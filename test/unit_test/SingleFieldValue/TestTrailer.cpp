#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, TrailerOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									  "Trailer: accept\r\n"
									  "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRAILER);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(std::string(ACCEPT), value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, TrailerOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Trailer: Accept-CH \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRAILER);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(std::string(ACCEPT_CH), value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, TrailerNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Trailer: Trailer \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRAILER);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}


TEST(TestSingleFieldValue, TrailerNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Trailer: content-length \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRAILER);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}
