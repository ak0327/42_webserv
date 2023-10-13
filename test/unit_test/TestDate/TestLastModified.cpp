#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "Date.hpp"
#include "gtest/gtest.h"

TEST(TestDate, LastModifiedOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		Date *date = dynamic_cast<Date *>(field_values);
		EXPECT_EQ("Wed", date->get_day_name());
		EXPECT_EQ("21", date->get_day());
		EXPECT_EQ("Oct", date->get_month());
		EXPECT_EQ("2015", date->get_year());
		EXPECT_EQ("07", date->get_hour());
		EXPECT_EQ("28", date->get_minute());
		EXPECT_EQ("00", date->get_second());
		EXPECT_EQ("GMT", date->get_gmt());
	} else {
		ADD_FAILURE() << "Date not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, LastModifiedOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Fri, 13 Oct 2023 00:21:45 GMT \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		Date *date = dynamic_cast<Date *>(field_values);

		EXPECT_EQ("Fri", date->get_day_name());
		EXPECT_EQ("13", date->get_day());
		EXPECT_EQ("Oct", date->get_month());
		EXPECT_EQ("2023", date->get_year());
		EXPECT_EQ("00", date->get_hour());
		EXPECT_EQ("21", date->get_minute());
		EXPECT_EQ("45", date->get_second());
		EXPECT_EQ("GMT", date->get_gmt());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << "Date not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, LastModifiedOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "LAST-Modified: Sun, 28 Feb 2021 00:21:45 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		Date *date = dynamic_cast<Date *>(field_values);

		EXPECT_EQ("Sun", date->get_day_name());
		EXPECT_EQ("28", date->get_day());
		EXPECT_EQ("Feb", date->get_month());
		EXPECT_EQ("2021", date->get_year());
		EXPECT_EQ("00", date->get_hour());
		EXPECT_EQ("21", date->get_minute());
		EXPECT_EQ("45", date->get_second());
		EXPECT_EQ("GMT", date->get_gmt());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << "Date not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, LastModifiedOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValues *field_values = request.get_field_values(field_name);
		Date *date = dynamic_cast<Date *>(field_values);

		EXPECT_EQ("Thu", date->get_day_name());
		EXPECT_EQ("29", date->get_day());
		EXPECT_EQ("Feb", date->get_month());
		EXPECT_EQ("2024", date->get_year());
		EXPECT_EQ("00", date->get_hour());
		EXPECT_EQ("21", date->get_minute());
		EXPECT_EQ("45", date->get_second());
		EXPECT_EQ("GMT", date->get_gmt());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << "Date not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestDate, LastModifiedNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed,  21  Oct  2015  07:28:00  GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 7:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Mon, 21 Oct 2015 07:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: WED, 21 Oct 2015 07:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 07:28:00 UTC\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Thu, 1 Jan 1581 00:00:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct -2015 07:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 07:60:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Hog, 21 Oct 2015 07:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG10) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 29 Feb 2021 07:28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG11) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 9223372036854775807 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG12) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 07:28:00: GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG13) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Wed, 21 Oct 2015 07;28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, LastModifiedNG14) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Last-Modified: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "Last-Modified: Wed, 21 Oct 2015 07::28:00 GMT\r\n"  // NG
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(LAST_MODIFIED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}
