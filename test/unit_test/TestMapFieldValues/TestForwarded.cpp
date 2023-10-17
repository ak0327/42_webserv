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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"for", "192.0.2.172"}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"for", "\"_mdn\""}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"For", "\"[2001:db8:cafe::17]:4711\""}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"for", "192.0.2.60"},
												  {"proto", "http"},
												  {"by", "203.0.113.43"}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"for", "192.0.2.43"},
												  {"a", "A"},
												  {"c", "d"}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"for", "\"_mdn\""},
												  {"a", "b"}};

		EXPECT_EQ(true, values.size() == ans.size());

		std::map<std::string, std::string>::iterator value_itr, ans_itr;
		value_itr = values.begin();
		ans_itr = ans.begin();
		while (value_itr != values.end() && ans_itr != ans.end()) {
			EXPECT_EQ(ans_itr->second, value_itr->second);
			++value_itr;
			++ans_itr;
		}
		EXPECT_TRUE(value_itr == values.end());
		EXPECT_TRUE(ans_itr == ans.end());

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
