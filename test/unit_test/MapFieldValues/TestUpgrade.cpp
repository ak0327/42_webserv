#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, UpgradeOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: example\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"example", ""}};

		EXPECT_EQ(actual_map.size(), expected_map.size());

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

TEST(TestMapFieldValues, UpgradeOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: HTTP/2.0\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"HTTP", "2.0"}};

		EXPECT_EQ(actual_map.size(), expected_map.size());

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

TEST(TestMapFieldValues, UpgradeOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: a_protocol/1   ,   example ,another_protocol/2.2, a,b, c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"a_protocol", "1"},
														   {"example", ""},
														   {"another_protocol", "2.2"},
														   {"a", ""},
														   {"b", ""},
														   {"c", ""}};

		EXPECT_EQ(actual_map.size(), expected_map.size());

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

TEST(TestMapFieldValues, UpgradeNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: example,,,\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, UpgradeNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: a/1 ; b/2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, UpgradeNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Upgrade: a//1 , b/2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(UPGRADE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
