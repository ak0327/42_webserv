#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, AltUsedOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: alternate.example.net\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "alternate.example.net"}};

		EXPECT_EQ(expected_map, actual_map);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "alt-used: example.com\r\n"
									 "alt-used: example.com:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "example.com"},
														   {std::string(PORT), "8080"}};

		EXPECT_EQ(expected_map, actual_map);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: 192.168.0.1:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "192.168.0.1"},
														   {std::string(PORT), "8080"}};

		EXPECT_EQ(expected_map, actual_map);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: [ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]:8080\r\n"
									 "Alt-Used: [ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "[abcd:ef01:2345:6789:abcd:ef01:2345:6789]"},
														   {std::string(PORT), "8080"}};

		EXPECT_EQ(expected_map, actual_map);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: localhost:8080\r\n"
									 "alt-used: localhost:8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{std::string(URI_HOST), "localhost"},
														   {std::string(PORT), "8080"}};

		EXPECT_EQ(expected_map, actual_map);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestMapFieldValues, AltUsedNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-used: :\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: example:\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: example:aaa\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: :8080\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapFieldValues, AltUsedNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Alt-Used: a:aaa\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ALT_USED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
