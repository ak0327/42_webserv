#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "MapSetFieldValues.hpp"
#include "gtest/gtest.h"

typedef std::set<std::map<std::string, std::string> > map_set;

TEST(TestMapSetFieldValues, ForwardedOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=192.0.2.172\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "192.0.2.172"},
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=\"_mdn\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "\"_mdn\""},
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: For=\"[2001:db8:cafe::17]:4711\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"For", "\"[2001:db8:cafe::17]:4711\""},
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "192.0.2.60"},
									 {"proto", "http"},
									 {"by", "203.0.113.43"}
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "forwarded: for=aaa\r\n"
									 "forwarded: a=hoge;a=huge\r\n"
									 "forwarded: for=192.0.2.43;a=b;c=d;a=A\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "192.0.2.43"},
									 {"c", "d"},
									 {"a", "A"}
									}};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=\"_mdn\";a=b, for=\"[2001:db8:cafe::17]\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "\"_mdn\""},
									 {"a", "b"},
									},
									{{"for", "\"[2001:db8:cafe::17]\""}},
									};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedOK7) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: for=\"_mdn\";a=b      , for=\"[2001:db8:cafe::17]\"\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	std::string field_name = std::string(FORWARDED);
	bool has_field_name = request.is_valid_field_name_registered(field_name);

	EXPECT_TRUE(has_field_name);

	if (has_field_name) {
		FieldValueBase *field_values = request.get_field_values(field_name);
		MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

		map_set actual_map_set = map_set_field_values->get_map_set_values();
		map_set expected_map_set = {{{"for", "\"_mdn\""},
											{"a", "b"},
									},
									{{"for", "\"[2001:db8:cafe::17]\""}},
		};

		EXPECT_EQ(expected_map_set, actual_map_set);

	} else {
		ADD_FAILURE() << field_name << " not found";
	}

	EXPECT_EQ(STATUS_OK, request.request_status());
}


////////////////////////////////////////////////////////////////////////////////

TEST(TestMapSetFieldValues, ForwardedNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: =\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a==b\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=A;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedNG4) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=A; b=B;\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedNG5) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=a ,, b=c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}

TEST(TestMapSetFieldValues, ForwardedNG6) {
	const std::string request_line = "GET /index.html HTTP/1.1\r\n"
									 "Host: example.com\r\n"
									 "Forwarded: a=a , , b=c\r\n"
									 "\r\n";
	HttpRequest request(request_line);
	bool has_field_name;
	std::string field_name = std::string(FORWARDED);

	has_field_name = request.is_valid_field_name_registered(field_name);
	EXPECT_FALSE(has_field_name);
	EXPECT_EQ(STATUS_OK, request.request_status());
}
