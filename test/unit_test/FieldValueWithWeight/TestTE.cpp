#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "FieldValueWithWeight.hpp"
#include "RequestLine.hpp"
#include "HttpMessageParser.hpp"
#include "ValueAndMapFieldValues.hpp"
#include "gtest/gtest.h"

namespace {

const std::string CODINGS = "codings";
const std::string WEIGHT = "weight";

}  // namespace

typedef std::map<std::string, std::string> string_map;

TEST(TestFieldValueWithWeight, TeOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: compress\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	// expected
	std::vector<std::string> expected_values = {"compress"};
	std::vector<string_map> expected_map_values = {{}};
	std::vector<double> expected_weights = {1.0};

	if (has_field_name) {

		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_set_itr = actual_set.begin();

		std::vector<std::string>::iterator expected_value_itr = expected_values.begin();
		std::vector<string_map>::iterator expected_map_values_itr = expected_map_values.begin();
		std::vector<double>::iterator expected_weight_itr = expected_weights.begin();

		if ((expected_values.size() != expected_weights.size())) {
			FAIL() << "[Error] expected values invalid";
		}

		while (actual_set_itr != actual_set.end()
				&& expected_value_itr != expected_values.end()
				&& expected_map_values_itr != expected_map_values.end()
				&& expected_weight_itr != expected_weights.end()) {
			ValueAndMapFieldValues *actual_value_and_map;
			actual_value_and_map = dynamic_cast<ValueAndMapFieldValues *>(actual_set_itr->get_field_value());

			// value
			std::string actual_value = actual_value_and_map->get_value();
			std::string expected_value = *expected_value_itr;
			// std::cout << CYAN << "value:[" << actual_value << "]" << RESET << std::endl;
			EXPECT_EQ(actual_value, expected_value);

			// map_values
			string_map actual_map = actual_value_and_map->get_value_map();
			string_map expected_map = *expected_map_values_itr;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			string_map::const_iterator actual_map_itr = actual_map.begin();
			string_map::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->first, expected_map_itr->first);
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);
				// std::cout << CYAN << "map:[" << actual_map_itr->first << "]=[" << actual_map_itr->second << "]" << RESET << std::endl;

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			// weight
			double actual_weight = actual_set_itr->get_weight();
			double expected_weight = *expected_weight_itr;
			// std::cout << CYAN << "weight:[" << actual_weight << "]" << RESET << std::endl;
			EXPECT_EQ(actual_weight, expected_weight);

			++actual_set_itr;
			++expected_value_itr;
			++expected_map_values_itr;
			++expected_weight_itr;
		}

		EXPECT_TRUE(actual_set_itr == actual_set.end());
		EXPECT_TRUE(expected_value_itr == expected_values.end());
		EXPECT_TRUE(expected_map_values_itr == expected_map_values.end());
		EXPECT_TRUE(expected_weight_itr == expected_weights.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, TeOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: trailers, deflate;q=0.5\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	// expected
	std::vector<std::string> expected_values = {"deflate", "trailers"};
	std::vector<string_map> expected_map_values = {{}, {}};
	std::vector<double> expected_weights = {0.5, 1.0};

	if (has_field_name) {

		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_set_itr = actual_set.begin();

		std::vector<std::string>::iterator expected_value_itr = expected_values.begin();
		std::vector<string_map>::iterator expected_map_values_itr = expected_map_values.begin();
		std::vector<double>::iterator expected_weight_itr = expected_weights.begin();

		if ((expected_values.size() != expected_weights.size())) {
			FAIL() << "[Error] expected values invalid";
		}

		while (actual_set_itr != actual_set.end()
			   && expected_value_itr != expected_values.end()
			   && expected_map_values_itr != expected_map_values.end()
			   && expected_weight_itr != expected_weights.end()) {
			ValueAndMapFieldValues *actual_value_and_map;
			actual_value_and_map = dynamic_cast<ValueAndMapFieldValues *>(actual_set_itr->get_field_value());

			// value
			std::string actual_value = actual_value_and_map->get_value();
			std::string expected_value = *expected_value_itr;
			// std::cout << CYAN << "value:[" << actual_value << "]" << RESET << std::endl;
			EXPECT_EQ(actual_value, expected_value);

			// map_values
			string_map actual_map = actual_value_and_map->get_value_map();
			string_map expected_map = *expected_map_values_itr;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			string_map::const_iterator actual_map_itr = actual_map.begin();
			string_map::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->first, expected_map_itr->first);
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);
				// std::cout << CYAN << "map:[" << actual_map_itr->first << "]=[" << actual_map_itr->second << "]" << RESET << std::endl;

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			// weight
			double actual_weight = actual_set_itr->get_weight();
			double expected_weight = *expected_weight_itr;
			// std::cout << CYAN << "weight:[" << actual_weight << "]" << RESET << std::endl;
			EXPECT_EQ(actual_weight, expected_weight);

			++actual_set_itr;
			++expected_value_itr;
			++expected_map_values_itr;
			++expected_weight_itr;
		}

		EXPECT_TRUE(actual_set_itr == actual_set.end());
		EXPECT_TRUE(expected_value_itr == expected_values.end());
		EXPECT_TRUE(expected_map_values_itr == expected_map_values.end());
		EXPECT_TRUE(expected_weight_itr == expected_weights.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}


TEST(TestFieldValueWithWeight, TeOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: a;b=c;d=e;q=0.5, A\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	// expected
	std::vector<std::string> expected_values = {"a", "A"};
	std::vector<string_map> expected_map_values = {{{"b", "c"}, {"d", "e"}}, {}};
	std::vector<double> expected_weights = {0.5, 1.0};

	if (has_field_name) {

		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_set_itr = actual_set.begin();

		std::vector<std::string>::iterator expected_value_itr = expected_values.begin();
		std::vector<string_map>::iterator expected_map_values_itr = expected_map_values.begin();
		std::vector<double>::iterator expected_weight_itr = expected_weights.begin();

		if ((expected_values.size() != expected_weights.size())) {
			FAIL() << "[Error] expected values invalid";
		}

		while (actual_set_itr != actual_set.end()
			   && expected_value_itr != expected_values.end()
			   && expected_map_values_itr != expected_map_values.end()
			   && expected_weight_itr != expected_weights.end()) {
			ValueAndMapFieldValues *actual_value_and_map;
			actual_value_and_map = dynamic_cast<ValueAndMapFieldValues *>(actual_set_itr->get_field_value());

			// value
			std::string actual_value = actual_value_and_map->get_value();
			std::string expected_value = *expected_value_itr;
			// std::cout << CYAN << "value:[" << actual_value << "]" << RESET << std::endl;
			EXPECT_EQ(actual_value, expected_value);

			// map_values
			string_map actual_map = actual_value_and_map->get_value_map();
			string_map expected_map = *expected_map_values_itr;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			string_map::const_iterator actual_map_itr = actual_map.begin();
			string_map::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->first, expected_map_itr->first);
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);
				// std::cout << CYAN << "map:[" << actual_map_itr->first << "]=[" << actual_map_itr->second << "]" << RESET << std::endl;

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			// weight
			double actual_weight = actual_set_itr->get_weight();
			double expected_weight = *expected_weight_itr;
			// std::cout << CYAN << "weight:[" << actual_weight << "]" << RESET << std::endl;
			EXPECT_EQ(actual_weight, expected_weight);

			++actual_set_itr;
			++expected_value_itr;
			++expected_map_values_itr;
			++expected_weight_itr;
		}

		EXPECT_TRUE(actual_set_itr == actual_set.end());
		EXPECT_TRUE(expected_value_itr == expected_values.end());
		EXPECT_TRUE(expected_map_values_itr == expected_map_values.end());
		EXPECT_TRUE(expected_weight_itr == expected_weights.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, TeOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: ;;\r\n"
									 "TE: ok;o=k;q=0.01\r\n"
									 "TE: ngngngng=aaaaa\r\n"
									 "TE: compress\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_TRUE(has_field_name);

	// expected
	std::vector<std::string> expected_values = {"compress"};
	std::vector<string_map> expected_map_values = {{}};
	std::vector<double> expected_weights = {1.0};

	if (has_field_name) {

		FieldValueBase *field_values = request.get_field_values(field_name);
		FieldValueWithWeightSet *data = dynamic_cast<FieldValueWithWeightSet *>(field_values);
		std::set<FieldValueWithWeight> actual_set = data->get_field_values();
		std::set<FieldValueWithWeight>::iterator actual_set_itr = actual_set.begin();

		std::vector<std::string>::iterator expected_value_itr = expected_values.begin();
		std::vector<string_map>::iterator expected_map_values_itr = expected_map_values.begin();
		std::vector<double>::iterator expected_weight_itr = expected_weights.begin();

		if ((expected_values.size() != expected_weights.size())) {
			FAIL() << "[Error] expected values invalid";
		}

		while (actual_set_itr != actual_set.end()
			   && expected_value_itr != expected_values.end()
			   && expected_map_values_itr != expected_map_values.end()
			   && expected_weight_itr != expected_weights.end()) {
			ValueAndMapFieldValues *actual_value_and_map;
			actual_value_and_map = dynamic_cast<ValueAndMapFieldValues *>(actual_set_itr->get_field_value());

			// value
			std::string actual_value = actual_value_and_map->get_value();
			std::string expected_value = *expected_value_itr;
			// std::cout << CYAN << "value:[" << actual_value << "]" << RESET << std::endl;
			EXPECT_EQ(actual_value, expected_value);

			// map_values
			string_map actual_map = actual_value_and_map->get_value_map();
			string_map expected_map = *expected_map_values_itr;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			string_map::const_iterator actual_map_itr = actual_map.begin();
			string_map::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->first, expected_map_itr->first);
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);
				// std::cout << CYAN << "map:[" << actual_map_itr->first << "]=[" << actual_map_itr->second << "]" << RESET << std::endl;

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			// weight
			double actual_weight = actual_set_itr->get_weight();
			double expected_weight = *expected_weight_itr;
			// std::cout << CYAN << "weight:[" << actual_weight << "]" << RESET << std::endl;
			EXPECT_EQ(actual_weight, expected_weight);

			++actual_set_itr;
			++expected_value_itr;
			++expected_map_values_itr;
			++expected_weight_itr;
		}

		EXPECT_TRUE(actual_set_itr == actual_set.end());
		EXPECT_TRUE(expected_value_itr == expected_values.end());
		EXPECT_TRUE(expected_map_values_itr == expected_map_values.end());
		EXPECT_TRUE(expected_weight_itr == expected_weights.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}


////////////////////////////////////////////////////////////////////////////////

TEST(TestFieldValueWithWeight, TeNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: ;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestFieldValueWithWeight, TeNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: a=b\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}


TEST(TestFieldValueWithWeight, TeNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "TE: a;b==c;;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(TE);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
