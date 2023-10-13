#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, SecFetchModeOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									  "Sec-Fetch-Mode: cors\r\n"
									  "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("cors", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: navigate\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("navigate", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: no-cors\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("no-cors", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: same-origin\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("same-origin", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: websocket\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("websocket", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: websocket\r\n"
									 "Sec-Fetch-mode: 123\r\n"
									 "sec-fetch-Mode: cors\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("cors", value->get_value());
	} else {
		ADD_FAILURE() << "SecFetchMode not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

/* field_name erase */

TEST(TestSingleFieldValue, SecFetchModeNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: cors\r\n"
									 "Sec-Fetch-Mode: aaa\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, SecFetchModeNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: +100\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSingleFieldValue, SecFetchModeNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Sec-Fetch-Mode: CORS\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SEC_FETCH_MODE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
