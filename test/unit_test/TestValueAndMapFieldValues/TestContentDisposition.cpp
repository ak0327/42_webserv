#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "ValueAndMapFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestValueAndMapFieldValues, ContentDispositionOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: inline \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		ValueAndMapFieldValues *value_and_map = dynamic_cast<ValueAndMapFieldValues *>(field_values);
		std::string actual_value = value_and_map->get_value();
		std::map<std::string, std::string> actual_map = value_and_map->get_value_map();

		// expected
		std::string expected_value = "inline";
		std::map<std::string, std::string> expected_map = {};

		// value
		EXPECT_EQ(expected_value, actual_value);

		// value_map
		EXPECT_EQ(true, actual_map.size() == expected_map.size());

		std::map<std::string, std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_map.begin();
		expected_itr = expected_map.begin();
		while (actual_itr != actual_map.end() && expected_itr != expected_map.end()) {
			EXPECT_EQ(expected_itr->second, actual_itr->second);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_map.end());
		EXPECT_TRUE(expected_itr == expected_map.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestValueAndMapFieldValues, ContentDispositionOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: attachment;a=\"A\";b=B\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		ValueAndMapFieldValues *value_and_map = dynamic_cast<ValueAndMapFieldValues *>(field_values);
		std::string actual_value = value_and_map->get_value();
		std::map<std::string, std::string> actual_map = value_and_map->get_value_map();

		// expected
		std::string expected_value = "attachment";
		std::map<std::string, std::string> expected_map = {{"a", "\"A\""},
														   {"b", "B"}};

		// value
		EXPECT_EQ(expected_value, actual_value);

		// value_map
		EXPECT_EQ(true, actual_map.size() == expected_map.size());

		std::map<std::string, std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_map.begin();
		expected_itr = expected_map.begin();
		while (actual_itr != actual_map.end() && expected_itr != expected_map.end()) {
			EXPECT_EQ(expected_itr->second, actual_itr->second);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_map.end());
		EXPECT_TRUE(expected_itr == expected_map.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestValueAndMapFieldValues, ContentDispositionOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: attachment;filename*=UTF-8''%E5%AE%9F%E9%A8%93%E3%83%87%E3%83%BC%E3%82%BF.csv\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		ValueAndMapFieldValues *value_and_map = dynamic_cast<ValueAndMapFieldValues *>(field_values);
		std::string actual_value = value_and_map->get_value();
		std::map<std::string, std::string> actual_map = value_and_map->get_value_map();

		// expected
		std::string expected_value = "attachment";
		std::map<std::string, std::string> expected_map = {{"filename*", "UTF-8''%E5%AE%9F%E9%A8%93%E3%83%87%E3%83%BC%E3%82%BF.csv"}};

		// value
		EXPECT_EQ(expected_value, actual_value);

		// value_map
		EXPECT_EQ(true, actual_map.size() == expected_map.size());

		std::map<std::string, std::string>::iterator actual_itr, expected_itr;
		actual_itr = actual_map.begin();
		expected_itr = expected_map.begin();
		while (actual_itr != actual_map.end() && expected_itr != expected_map.end()) {
			EXPECT_EQ(expected_itr->second, actual_itr->second);
			++actual_itr;
			++expected_itr;
		}
		EXPECT_TRUE(actual_itr == actual_map.end());
		EXPECT_TRUE(expected_itr == expected_map.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


////////////////////////////////////////////////////////////////////////////////

TEST(TestValueAndMapFieldValues, ContentDispositionNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: ;;;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestValueAndMapFieldValues, ContentDispositionNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: a; b=c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestValueAndMapFieldValues, ContentDispositionNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: a=b\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestValueAndMapFieldValues, ContentDispositionNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Disposition: a=b=c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_DISPOSITION);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
