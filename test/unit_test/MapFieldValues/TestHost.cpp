#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, HostOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "example.com"}};

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

TEST(TestMapFieldValues, HostOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "example.com"},
														   {std::string(PORT), "8080"}};

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

TEST(TestMapFieldValues, HostOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: 192.168.0.1:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "192.168.0.1"},
														   {std::string(PORT), "8080"}};

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

TEST(TestMapFieldValues, HostOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: [ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]"},
														   {std::string(PORT), "8080"}};

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

TEST(TestMapFieldValues, HostOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: localhost:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "localhost"},
														   {std::string(PORT), "8080"}};

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

TEST(TestMapFieldValues, HostNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Host: example.com\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestMapFieldValues, HostNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example:\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestMapFieldValues, HostNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example:aaa\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestMapFieldValues, HostNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: :8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestMapFieldValues, HostNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: a:aaa\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(HOST);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}
