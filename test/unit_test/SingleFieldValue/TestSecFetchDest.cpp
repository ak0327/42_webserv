#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, SecFechDestOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Dest: audio\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_DEST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);
	std::string expected = "audio";

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(expected, value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, SecFechDestOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Dest: empty    \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_DEST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);
	std::string expected = "empty";

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ(expected, value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestSingleFieldValue, SecFechDestNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Dest: EMPTY \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_DEST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}


TEST(TestSingleFieldValue, SecFechDestNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Dest: \"audio\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_DEST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.status_code());
}
