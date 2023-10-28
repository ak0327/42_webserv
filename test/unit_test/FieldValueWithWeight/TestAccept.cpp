#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "FieldValueWithWeight.hpp"
#include "RequestLine.hpp"
#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

namespace {

const std::string TYPE = "type";
const std::string SUBTYPE = "subtype";
const std::string WEIGHT = "weight";

}  // namespace

TEST(TestFieldValueWithWeight, AcceptOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: text/html\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "text"},
				 {SUBTYPE, "html"},
				 {WEIGHT, "1.0"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: text/html; q=1.0\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "text"},
				 {SUBTYPE, "html"},
				 {WEIGHT, "1.0"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: text/html; q=0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "text"},
				 {SUBTYPE, "html"},
				 {WEIGHT, "0.5"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q=0.5 , b/B ; q=0.1 ,c/C\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "b"}, {SUBTYPE, "B"}, {WEIGHT, "0.1"}},
				{{TYPE, "a"}, {SUBTYPE, "A"}, {WEIGHT, "0.5"}},
				{{TYPE, "c"}, {SUBTYPE, "C"}, {WEIGHT, "1.0"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A;q=0, b/B  ;    q=1\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "a"}, {SUBTYPE, "A"}, {WEIGHT, "0"}},
				{{TYPE, "b"}, {SUBTYPE, "B"}, {WEIGHT, "1"}},
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A;q=0, b/B; q=1, */*; q=0.4, */c;q=0.5, d/*;q=0.6\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "a"}, {SUBTYPE, "A"}, {WEIGHT, "0"}},
				{{TYPE, "*"}, {SUBTYPE, "*"}, {WEIGHT, "0.4"}},
				{{TYPE, "*"}, {SUBTYPE, "c"}, {WEIGHT, "0.5"}},
				{{TYPE, "d"}, {SUBTYPE, "*"}, {WEIGHT, "0.6"}},
				{{TYPE, "b"}, {SUBTYPE, "B"}, {WEIGHT, "1"}},
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptOK7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: text/html\r\n"
									 "Accept: text/html\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_itr = actual_set.begin();

		std::vector<std::map<std::string, std::string>> expected_set = {
				{{TYPE, "text"},
				 {SUBTYPE, "html"},
				 {WEIGHT, "1.0"}}
		};
		std::vector<std::map<std::string, std::string>>::iterator expected_itr = expected_set.begin();

		while (actual_itr != actual_set.end() && expected_itr != expected_set.end()) {
			MediaType *media_type = dynamic_cast<MediaType *>(actual_itr->get_field_value());
			double weight = actual_itr->get_weight();

			std::string expected_type = (*expected_itr)[TYPE];
			std::string expected_subtype = (*expected_itr)[SUBTYPE];
			double expected_weight = HttpMessageParser::to_floating_num((*expected_itr)[WEIGHT], 3, NULL);

			EXPECT_EQ(expected_type, media_type->get_type());
			EXPECT_EQ(expected_subtype, media_type->get_subtype());
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

TEST(TestFieldValueWithWeight, AcceptNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a; q=0.1\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q=\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q=1.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q=1.0000000\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestFieldValueWithWeight, AcceptNG7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Accept: a/A; q=1.0000000\r\n"
									 "Accept: a/A; q=1.0000000\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(ACCEPT);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}