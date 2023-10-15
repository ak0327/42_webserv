#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "Date.hpp"
#include "gtest/gtest.h"

TEST(TestDate, DateOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

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
		EXPECT_EQ(IMF_FIXDATE, date->get_format());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, DateOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Fri, 13 Oct 2023 00:21:45 GMT \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

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
		EXPECT_EQ(IMF_FIXDATE, date->get_format());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, DateOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Sun, 28 Feb 2021 00:21:45 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

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
		EXPECT_EQ(IMF_FIXDATE, date->get_format());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestDate, DateOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

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
		EXPECT_EQ(IMF_FIXDATE, date->get_format());
		EXPECT_EQ(true, date->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestDate, DateNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed,  21  Oct  2015  07:28:00  GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 7:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Mon, 21 Oct 2015 07:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: WED, 21 Oct 2015 07:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 07:28:00 UTC\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Thu, 1 Jan 1581 00:00:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct -2015 07:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 07:60:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Hog, 21 Oct 2015 07:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG10) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 29 Feb 2021 07:28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG11) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 9223372036854775807 Oct 2015 07:28:00 GMT\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG12) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 07:28:00: GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG13) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Wed, 21 Oct 2015 07;28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG14) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "Date: Wed, 21 Oct 2015 07::28:00 GMT\r\n"  // ERR
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestDate, DateNG15) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "Date: Thu, 29 Feb 2024 00:21:45 GMT\r\n"  // OK
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(DATE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
