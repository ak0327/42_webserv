#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MapSetFieldValues.hpp"
#include "gtest/gtest.h"

typedef std::set<std::map<std::string, std::string> > map_set;

TEST(TestMapSetFieldValues, LinkOK1) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: <https://example.com>\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(URI_REFERENCE), "https://example.com"},
									 }};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, LinkOK2) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: <example1>,<example2>, <example3> , <example4>  , <example5>\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(URI_REFERENCE), "example1"}},
									{{std::string(URI_REFERENCE), "example2"}},
									{{std::string(URI_REFERENCE), "example3"}},
									{{std::string(URI_REFERENCE), "example4"}},
									{{std::string(URI_REFERENCE), "example5"}},};


		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, LinkOK3) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: <https://example.com>; rel=\"preconnect\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(URI_REFERENCE), "https://example.com"},
									 {"rel", "\"preconnect\""}
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, LinkOK4) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: <https://example.com>; rel=\"preconnect\"  ; a=A;b=B  ; c=C\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{std::string(URI_REFERENCE), "https://example.com"},
									 {"rel", "\"preconnect\""},
									 {"a", "A"},
									 {"b", "B"},
									 {"c", "C"},
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

TEST(TestMapSetFieldValues, LinkOK5) {

	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: "
									 "<example1>;a,"
									 "<example2>,"
									 " <example3>  ; b=B ; c=\"this is c\" ,"
									 " <example4?#>  ,"
									 " <example5>     ;d\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {
				{
						{std::string(URI_REFERENCE), "example1"},
						{"a", ""},
				}, {
						{std::string(URI_REFERENCE), "example2"},
				}, {
						{std::string(URI_REFERENCE), "example3"},
						{"b", "B"},
						{"c", "\"this is c\""},
				}, {
						{std::string(URI_REFERENCE), "example4?#"},
				}, {
						{std::string(URI_REFERENCE), "example5"},
						{"d", ""},
				}};


		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.get_status_code());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestMapSetFieldValues, LinkNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Link: example.com\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(LINK);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.get_status_code());
}
