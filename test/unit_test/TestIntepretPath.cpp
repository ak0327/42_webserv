#include <climits>
#include <string>
#include "../../srcs/HttpResponse/DELETE/DeleteHttpResponse/DeleteHttpResponse.hpp"
#include "gtest/gtest.h"

TEST(Interpretpath, test1) {
	// std::string	folda_name;
	// std::string	file_name;
	DeleteHttpResponse test;

	EXPECT_EQ("/", test.get_location_from_requestline_targeturi("http://localhost:8000/"));
	// EXPECT_EQ(folda_name, "/");
	// EXPECT_EQ(file_name, "");
}

TEST(Interpretpath, test2) {
	// std::string	folda_name;
	// std::string	file_name;
	DeleteHttpResponse test;

	EXPECT_EQ("/aaa", test.get_location_from_requestline_targeturi("http://localhost:8000/aaa"));
	// EXPECT_EQ(folda_name, "/");
	// EXPECT_EQ(file_name, "aaa");
}

TEST(Interpretpath, test3) {
	// std::string	folda_name;
	// std::string	file_name;
	DeleteHttpResponse test;

	EXPECT_EQ("/aaa/", test.get_location_from_requestline_targeturi("http://localhost:8000/aaa/"));
	// EXPECT_EQ(folda_name, "/aaa/");
	// EXPECT_EQ(file_name, "");
}

TEST(Interpretpath, test4) {
	// std::string	folda_name;
	// std::string	file_name;
	DeleteHttpResponse test;

	EXPECT_EQ("/aaa/bbb/index.html", test.get_location_from_requestline_targeturi("http://localhost:8000/aaa/bbb/index.html"));
	// EXPECT_EQ(folda_name, "/aaa/bbb/");
	// EXPECT_EQ(file_name, "index.html");
}
