#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "MediaType.hpp"
#include "RequestLine.hpp"
#include "gtest/gtest.h"

TEST(TestMediaType, ContentTypeOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: text/html\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MediaType *data = dynamic_cast<MediaType *>(field_values);
		if (data->is_err()) {
			FAIL() << "[Error] Parse Failed";
		}

		//----------------------------------------------------------------------

		EXPECT_EQ("text", data->get_type());
		EXPECT_EQ("html", data->get_subtype());

		//----------------------------------------------------------------------

		std::map<std::string, std::string> actual_param = data->get_parameters();
		std::map<std::string, std::string> expected_param = {};

		EXPECT_EQ(actual_param, expected_param);
		//----------------------------------------------------------------------

		EXPECT_EQ(true, data->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMediaType, ContentTypeOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: text/html; charset=utf-8\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MediaType *data = dynamic_cast<MediaType *>(field_values);
		if (data->is_err()) {
			FAIL() << "[Error] Parse Failed";
		}

		//----------------------------------------------------------------------

		EXPECT_EQ("text", data->get_type());
		EXPECT_EQ("html", data->get_subtype());

		//----------------------------------------------------------------------

		std::map<std::string, std::string> actual_param = data->get_parameters();
		std::map<std::string, std::string> expected_param = {{"charset", "utf-8"}};

		EXPECT_EQ(actual_param, expected_param);
		//----------------------------------------------------------------------

		EXPECT_EQ(true, data->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMediaType, ContentTypeOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: multipart/form-data ; charset=utf-8 ; boundary=something\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MediaType *data = dynamic_cast<MediaType *>(field_values);
		if (data->is_err()) {
			FAIL() << "[Error] Parse Failed";
		}

		//----------------------------------------------------------------------

		EXPECT_EQ("multipart", data->get_type());
		EXPECT_EQ("form-data", data->get_subtype());

		//----------------------------------------------------------------------

		std::map<std::string, std::string> actual_param = data->get_parameters();
		std::map<std::string, std::string> expected_param = {{"charset", "utf-8"},
															 {"boundary", "something"}};

		EXPECT_EQ(actual_param, expected_param);
		//----------------------------------------------------------------------

		EXPECT_EQ(true, data->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMediaType, ContentTypeOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: multipart/form-data ; charset=\"utf-8  sp ok \"   ; a=b  \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MediaType *data = dynamic_cast<MediaType *>(field_values);
		if (data->is_err()) {
			FAIL() << "[Error] Parse Failed";
		}

		//----------------------------------------------------------------------

		EXPECT_EQ("multipart", data->get_type());
		EXPECT_EQ("form-data", data->get_subtype());

		//----------------------------------------------------------------------

		std::map<std::string, std::string> actual_param = data->get_parameters();
		std::map<std::string, std::string> expected_param = {{"charset", "\"utf-8  sp ok \""},
															 {"a", "b"}};

		EXPECT_EQ(actual_param, expected_param);
		//----------------------------------------------------------------------

		EXPECT_EQ(true, data->is_ok());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestMediaType, ContentTypeNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: text\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMediaType, ContentTypeNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: text/html;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMediaType, ContentTypeNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Content-Type: text/html; hoge\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(CONTENT_TYPE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
