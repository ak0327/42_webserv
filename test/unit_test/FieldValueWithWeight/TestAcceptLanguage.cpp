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

TEST(TestFieldValueWithWeight, AcceptLanguageOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: *\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

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

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: *;q=0.51\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

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

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"}, {WEIGHT, "0.5"}},
				{{CODINGS, "de"}, {WEIGHT, "0.7"}},
				{{CODINGS, "en"}, {WEIGHT, "0.8"}},
				{{CODINGS, "fr"}, {WEIGHT, "0.9"}},
				{{CODINGS, "fr-CH"}, {WEIGHT, "1.0"}},
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

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: ;;;\r\n"
									 "Accept-Language: A; q=0.5, *;q=0\r\n"
									 "Accept-Language: a=b;\r\n"
									 "Accept-Language: A;q=0.9, *;q=0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "*"}, {WEIGHT, "0.5"}},
				{{CODINGS, "A"}, {WEIGHT, "0.9"}},
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

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: aaa-1-12345678\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{CODINGS, "aaa-1-12345678"},
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

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestFieldValueWithWeight, AcceptLanguageNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: ;;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: ;  ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: a;b;c;d\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: a;q==0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: a;q = 0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: a;q= \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG8) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: 123 \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptLanguageNG9) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept-Language: aaabbbccc \r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT_LANGUAGE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}


