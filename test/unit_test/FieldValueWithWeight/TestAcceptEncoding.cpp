#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "FieldValueWithWeight.hpp"
#include "RequestLine.hpp"
#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

namespace {

const std::string CODINGS = "codings";
const std::string WEIGHT = "weight";

}  // namespace

TEST(TestFieldValueWithWeight, AcceptEncodingOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: *\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"},
				 {WEIGHT, "1.0"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			SingleFieldValue *field_value = dynamic_cast<SingleFieldValue *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_codings = (*expected_itr)[CODINGS];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_codings, field_value->get_value());
			EXPECT_EQ(expected_weight, weight);

			++actual_itr;
			++expected_itr;
		}

		EXPECT_TRUE(expected_itr == expected_set.end());
		EXPECT_TRUE(actual_itr == actual_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: *;q=0.51\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"},
				 {WEIGHT, "0.51"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			SingleFieldValue *field_value = dynamic_cast<SingleFieldValue *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_codings = (*expected_itr)[CODINGS];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_codings, field_value->get_value());
			EXPECT_EQ(expected_weight, weight);

			++actual_itr;
			++expected_itr;
		}

		EXPECT_TRUE(expected_itr == expected_set.end());
		EXPECT_TRUE(actual_itr == actual_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"}, {WEIGHT, "0"}},
				{{CODINGS, "identity"}, {WEIGHT, "0.5"}},
				{{CODINGS, "gzip"}, {WEIGHT, "1.0"}},
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			SingleFieldValue *field_value = dynamic_cast<SingleFieldValue *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_codings = (*expected_itr)[CODINGS];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_codings, field_value->get_value());
			EXPECT_EQ(expected_weight, weight);

			++actual_itr;
			++expected_itr;
		}

		EXPECT_TRUE(expected_itr == expected_set.end());
		EXPECT_TRUE(actual_itr == actual_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: ;;;\r\n"
									 "Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0\r\n"
									 "Accept-Encoding: a=b;\r\n"
									 "Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"}, {WEIGHT, "0"}},
				{{CODINGS, "identity"}, {WEIGHT, "0.5"}},
				{{CODINGS, "gzip"}, {WEIGHT, "1.0"}},
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			SingleFieldValue *field_value = dynamic_cast<SingleFieldValue *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_codings = (*expected_itr)[CODINGS];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_codings, field_value->get_value());
			EXPECT_EQ(expected_weight, weight);

			++actual_itr;
			++expected_itr;
		}

		EXPECT_TRUE(expected_itr == expected_set.end());
		EXPECT_TRUE(actual_itr == actual_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestFieldValueWithWeight, AcceptEncodingNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: ;;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: ;  ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: a;b;c;d\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: a;q==0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: a;q = 0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, AcceptEncodingNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Encoding: a;q= \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_ENCODING);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
