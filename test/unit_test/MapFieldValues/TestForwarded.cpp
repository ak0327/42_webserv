#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, ForwardedOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=192.0.2.172\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"for", "192.0.2.172"}};

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

TEST(TestMapFieldValues, ForwardedOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=\"_mdn\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"for", "\"_mdn\""}};

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

TEST(TestMapFieldValues, ForwardedOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: For=\"[2001:db8:cafe::17]:4711\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"For", "\"[2001:db8:cafe::17]:4711\""}};

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

TEST(TestMapFieldValues, ForwardedOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"for", "192.0.2.60"},
														   {"proto", "http"},
														   {"by", "203.0.113.43"}};

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

TEST(TestMapFieldValues, ForwardedOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "forwarded: for=aaa\r\n"
									 "forwarded: a=hoge; a=huge\r\n"
									 "forwarded: for=192.0.2.43; a=b; c=d; a=A\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"for", "192.0.2.43"},
														   {"a", "A"},
														   {"c", "d"}};

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

TEST(TestMapFieldValues, ForwardedOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=\"_mdn\"; a=b\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"for", "\"_mdn\""},
														   {"a", "b"}};

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

TEST(TestMapFieldValues, ForwardedNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: =\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, ForwardedNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a==b\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, ForwardedNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=A;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, ForwardedNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=A; b=B;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
