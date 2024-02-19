#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "HttpResponse.hpp"

TEST(HttpResponseGet, CGIGetInterPreter) {
	std::string file_path;
	std::vector<std::string> expected, actual;
	Result<std::vector<std::string>, int> result;

	file_path = "www/cgi-bin/hello.py";
	expected = {"/usr/bin/env", "python3"};
	result = get_interpreter(file_path);
	actual = result.get_ok_value();
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(expected, actual);

	file_path = "www/cgi-bin/page.php";
	expected = {"/usr/bin/env", "php"};
	result = get_interpreter(file_path);
	actual = result.get_ok_value();
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(expected, actual);

	file_path = "www/index.html";
	result = get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());

	file_path = "file_not_exist";
	result = get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());

	file_path = "test/unit_test/HttpResponse/empty_file_for_get_interpreter";
	result = get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());
}
