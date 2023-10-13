#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, Connection1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									  "Connection: close\r\n"
									  "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("close", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: CLOSE\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("close", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: ClosE\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("close", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: keep-alive\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("keep-alive", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: Keep-Alive\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("keep-alive", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSingleFieldValue, Connection6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: Keep-Alive         \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("keep-alive", value->get_value());
	} else {
		ADD_FAILURE() << "Connection not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestSingleFieldValue, Connection7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: closee \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: -1\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: keep_alive\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection10) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: keepalive\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestSingleFieldValue, Connection11) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Connection: close\r\n"
									 "Connection: 600\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	const std::string field_name = std::string(CONNECTION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
