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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"PHPSESSID", "298zf09hf012fh2"}};

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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"PHPSESSID", "298zf09hf012fh2"},
														   {"csrftoken", "u32t4o3tb3gg43"},
														   {"_gat", "1"}};

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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"PHPSESSID", "298zf09hf012fh2"},
														   {"csrftoken", "u32t4o3tb3gg43"},
														   {"_gat", "1"}};

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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"PHPSESSID", "\"298zf09hf012fh2\""}};

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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"PHPSESSID", "!#$%&'()*+-./012345689:<=>?@[]^_`{|}~"}};

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
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();
		std::map<std::string, std::string> expected_map = {{"a", "E"}};

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
