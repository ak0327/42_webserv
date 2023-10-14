#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, AccessControlRequestMethod1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									  "Access-Control-Request-Method: GET\r\n"
									  "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("GET", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: POST\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("POST", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: DELETE\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("DELETE", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: get\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: GET\r\n"
									 "Access-Control-Request-Method: hoge\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: HEAD\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: PUT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: CONNECT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, AccessControlRequestMethod9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Access-Control-Request-Method: 123\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(ACCESS_CONTROL_REQUEST_METHOD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
