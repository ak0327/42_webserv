#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMultiFieldValues, TransferEncodingOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: chunked\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"chunked"};

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

TEST(TestMultiFieldValues, TransferEncodingOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: gzip, chunked \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"gzip", "chunked"};

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

TEST(TestMultiFieldValues, TransferEncodingOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: a, hoge; param=\"value with space\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"a", "hoge; param=\"value with space\""};

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

TEST(TestMultiFieldValues, TransferEncodingOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: chunked; param1=value1,"
									 " hoge; param2=\"value with space and \'quote\'\"  ,"
									 "    a   ; b=\"\ttab\" \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MultiFieldValues *multi_field_values = dynamic_cast<MultiFieldValues *>(field_values);
		std::set<std::string> actual_values = multi_field_values->get_values();
		std::set<std::string> expected_values = {"chunked; param1=value1",
									 "hoge; param2=\"value with space and \'quote\'\"",
									 "a   ; b=\"\ttab\""};

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


TEST(TestMultiFieldValues, TransferEncodingNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: ,,a \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


TEST(TestMultiFieldValues, TransferEncodingNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: a=b \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMultiFieldValues, TransferEncodingNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Transfer-Encoding: hoge;;hoge\t \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TRANSFER_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
