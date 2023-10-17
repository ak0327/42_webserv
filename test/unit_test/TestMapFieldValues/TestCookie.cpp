#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MultiFieldValues.hpp"
#include "gtest/gtest.h"

TEST(TestMapFieldValues, CookieOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2 \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"PHPSESSID", "298zf09hf012fh2"}};

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

TEST(TestMapFieldValues, CookieOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"PHPSESSID", "298zf09hf012fh2"},
												  {"csrftoken", "u32t4o3tb3gg43"},
												  {"_gat", "1"}};

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

TEST(TestMapFieldValues, CookieOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b \r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"PHPSESSID", "298zf09hf012fh2"},
												  {"csrftoken", "u32t4o3tb3gg43"},
												  {"_gat", "1"}};

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

TEST(TestMapFieldValues, CookieOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b \r\n"
									 "Cookie: PHPSESSID=\"298zf09hf012fh2\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"PHPSESSID", "\"298zf09hf012fh2\""}};

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

TEST(TestMapFieldValues, CookieOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b \r\n"
									 "Cookie: PHPSESSID=!#$%&'()*+-./012345689:<=>?@[]^_`{|}~\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"PHPSESSID", "!#$%&'()*+-./012345689:<=>?@[]^_`{|}~"}};

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

TEST(TestMapFieldValues, CookieOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b \r\n"
									 "Cookie: a=A; b=B \r\n"
									 "Cookie: c=d \r\n"
									 "Cookie: a=E \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> values = multi_field_values->get_value_map();
		std::map<std::string, std::string> ans = {{"a", "E"}};

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

TEST(TestMapFieldValues, CookieNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2;     csrftoken=u32t4o3tb3gg43\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=\"298zf09hf012fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012fh2\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012 fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012,fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012\"fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012;fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: PHPSESSID=298zf09hf012\\fh2\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG10) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG11) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b ; ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapFieldValues, CookieNG12) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Cookie: a=b;;;;;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(COOKIE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
