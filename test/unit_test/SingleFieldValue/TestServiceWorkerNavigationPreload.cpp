#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "SingleFieldValue.hpp"
#include "gtest/gtest.h"

TEST(TestSingleFieldValue, ServiceWorkerNavigationPreloadOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									  "Service-Worker-Navigation-Preload: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
									  "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SERVICE_WORKER_NAVIGATION_PRELOAD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, ServiceWorkerNavigationPreloadOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Service-Worker-Navigation-Preload: abc123 \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SERVICE_WORKER_NAVIGATION_PRELOAD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("abc123", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}

TEST(TestSingleFieldValue, ServiceWorkerNavigationPreloadOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Service-Worker-Navigation-Preload: abc \r\n"
									 "Service-Worker-Navigation-Preload: 123 \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(SERVICE_WORKER_NAVIGATION_PRELOAD);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		SingleFieldValue *value = dynamic_cast<SingleFieldValue *>(field_values);
		EXPECT_EQ("123", value->get_value());
	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.status_code());
}
