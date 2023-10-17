#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, CacheControlOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: max-age=604800\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"max-age", "604800"}};

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

TEST(TestMapFieldValues, CacheControlOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: public, max-age=604800, immutable\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"public", ""},
												  {"max-age", "604800"},
												  {"immutable", ""}};

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

TEST(TestMapFieldValues, CacheControlOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: must-understand, no-store\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"must-understand", ""},
												  {"no-store", ""}};

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

TEST(TestMapFieldValues, CacheControlOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: max-age=604800, stale-while-revalidate=86400\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"max-age", "604800"},
												  {"stale-while-revalidate", "86400"}};

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

TEST(TestMapFieldValues, CacheControlOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a=123\r\n"
									 "Cache-Control: abc\r\n"
									 "Cache-Control: a, b, c, d, e, a=A\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"a", "A"},
												  {"b", ""},
												  {"c", ""},
												  {"d", ""},
												  {"e", ""}};

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

TEST(TestMapFieldValues, CacheControlOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a=\"123\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"a", "\"123\""}};

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

TEST(TestMapFieldValues, CacheControlNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a=\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CacheControlNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a=\"123\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CacheControlNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a=b\r\n"
									 "Cache-Control: a= 123\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CacheControlNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a,b,,;,,c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CacheControlNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cache-Control: a,b         ,.,,,c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CACHE_CONTROL);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
