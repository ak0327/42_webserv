#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, FromOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: webmaster@example.org  \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);


	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);

		std::string actual = value->get_value();
		std::string expected = "webmaster@example.org";

		EXPECT_EQ(expected, actual);
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: test@test\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);


	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);

		std::string actual = value->get_value();
		std::string expected = "test@test";

		EXPECT_EQ(expected, actual);
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: test.test@test.te.st\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);


	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);

		std::string actual = value->get_value();
		std::string expected = "test.test@test.te.st";

		EXPECT_EQ(expected, actual);
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: a@b\r\n"
									 "From: test.test@[test.te.st]\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);


	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);

		std::string actual = value->get_value();
		std::string expected = "test.test@[test.te.st]";

		EXPECT_EQ(expected, actual);
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestSingleFieldValue, FromNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng@\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng@@ng.ng\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng@ng..ng\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng@.\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: .@ng.ng\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestSingleFieldValue, FromNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "From: ng@ng.ng.\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FROM);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
