#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MapSetFieldValues.hpp"
#include "gtest/gtest.h"

typedef std::set<std::map<std::string, std::string> > map_set;

TEST(TestMapSetFieldValues, ViaOK1) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Via: 1.1 vegur\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(VIA);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(RECEIVED_PROTOCOL), "1.1"},
									 {std::string(RECEIVED_BY), "vegur"},
									 {std::string(COMMENT), ""},
									 }};


		EXPECT_EQ(actual_map_set.size(), expected_map_set.size());

		map_set::const_iterator actual_map_set_itr = actual_map_set.begin();
		map_set::const_iterator expected_map_set_itr = expected_map_set.begin();

		while (actual_map_set_itr != actual_map_set.end() && expected_map_set_itr != expected_map_set.end()) {
			std::map<std::string, std::string> actual_map = *actual_map_set_itr;
			std::map<std::string, std::string> expected_map = *expected_map_set_itr;;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			std::map<std::string, std::string>::const_iterator actual_map_itr = actual_map.begin();
			std::map<std::string, std::string>::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			++actual_map_set_itr;
			++expected_map_set_itr;
		}
		EXPECT_TRUE(actual_map_set_itr == actual_map_set.end());
		EXPECT_TRUE(expected_map_set_itr == expected_map_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, ViaOK2) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Via: 1.0 fred, 1.1 p.example.net\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(VIA);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(RECEIVED_PROTOCOL), "1.0"},
									 {std::string(RECEIVED_BY), "fred"},
									 {std::string(COMMENT), ""},
									},
									{{std::string(RECEIVED_PROTOCOL), "1.1"},
									 {std::string(RECEIVED_BY), "p.example.net"},
									 {std::string(COMMENT), ""},
									}};


		EXPECT_EQ(actual_map_set.size(), expected_map_set.size());

		map_set::const_iterator actual_map_set_itr = actual_map_set.begin();
		map_set::const_iterator expected_map_set_itr = expected_map_set.begin();

		while (actual_map_set_itr != actual_map_set.end() && expected_map_set_itr != expected_map_set.end()) {
			std::map<std::string, std::string> actual_map = *actual_map_set_itr;
			std::map<std::string, std::string> expected_map = *expected_map_set_itr;;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			std::map<std::string, std::string>::const_iterator actual_map_itr = actual_map.begin();
			std::map<std::string, std::string>::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			++actual_map_set_itr;
			++expected_map_set_itr;
		}
		EXPECT_TRUE(actual_map_set_itr == actual_map_set.end());
		EXPECT_TRUE(expected_map_set_itr == expected_map_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, ViaOK3) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Via: 1.0 fred, 1.1 p.example.net , HTTP/1.1 GWA (this is comment)\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(VIA);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(RECEIVED_PROTOCOL), "1.0"},
											{std::string(RECEIVED_BY), "fred"},
											{std::string(COMMENT), ""},
									},
									{{std::string(RECEIVED_PROTOCOL), "1.1"},
											{std::string(RECEIVED_BY), "p.example.net"},
											{std::string(COMMENT), ""},
									},
									{{std::string(RECEIVED_PROTOCOL), "HTTP/1.1"},
											{std::string(RECEIVED_BY), "GWA"},
											{std::string(COMMENT), "(this is comment)"},
									}};


		EXPECT_EQ(actual_map_set.size(), expected_map_set.size());

		map_set::const_iterator actual_map_set_itr = actual_map_set.begin();
		map_set::const_iterator expected_map_set_itr = expected_map_set.begin();

		while (actual_map_set_itr != actual_map_set.end() && expected_map_set_itr != expected_map_set.end()) {
			std::map<std::string, std::string> actual_map = *actual_map_set_itr;
			std::map<std::string, std::string> expected_map = *expected_map_set_itr;;

			EXPECT_EQ(actual_map.size(), expected_map.size());
			std::map<std::string, std::string>::const_iterator actual_map_itr = actual_map.begin();
			std::map<std::string, std::string>::const_iterator expected_map_itr = expected_map.begin();

			while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
				EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);

				++actual_map_itr;
				++expected_map_itr;
			}
			EXPECT_TRUE(actual_map_itr == actual_map.end());
			EXPECT_TRUE(expected_map_itr == expected_map.end());

			++actual_map_set_itr;
			++expected_map_set_itr;
		}
		EXPECT_TRUE(actual_map_set_itr == actual_map_set.end());
		EXPECT_TRUE(expected_map_set_itr == expected_map_set.end());

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestMapSetFieldValues, ViaNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Via: example\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(VIA);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, ViaNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Via: 1.0  fred, 1.1 p.example.net\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(VIA);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
