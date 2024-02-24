#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, IfRangeOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Range:  Wed, 21 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_RANGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);
	std::string actual_value = "Wed, 21 Oct 2015 07:28:00 GMT";

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(actual_value, value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, IfRangeOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Range: \"ABC\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_RANGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);
	std::string actual_value = "\"ABC\"";

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(actual_value, value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestSingleFieldValue, IfRangeNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Range: aaa \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_RANGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}


TEST(TestSingleFieldValue, IfRangeNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Range: a b c \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_RANGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, IfRangeNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "If-Range:  Wed, 21 Oct 2015 07:28:00 GMT\r\n"
									 "If-Range:  Wed, 21 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(IF_RANGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.status_code());
}
