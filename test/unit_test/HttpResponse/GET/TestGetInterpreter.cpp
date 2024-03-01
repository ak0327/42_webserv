#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "TestCgiHandler.hpp"

TEST(HttpResponseGet, CGIGetInterPreter) {
	std::string file_path;
	std::vector<std::string> expected, actual;
	Result<std::vector<std::string>, ProcResult> result;

	file_path = "html/cgi-bin/hello.py";
	expected = {"/usr/bin/env", "python3"};
	result = CgiHandlerFriend::get_interpreter(file_path);
	actual = result.get_ok_value();
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(expected, actual);

	file_path = "html/cgi-bin/page.php";
	expected = {"/opt/homebrew/bin/php"};
	result = CgiHandlerFriend::get_interpreter(file_path);
	actual = result.get_ok_value();
	EXPECT_TRUE(result.is_ok());
	EXPECT_EQ(expected, actual);

	file_path = "html/index.html";
	result = CgiHandlerFriend::get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());

	file_path = "file_not_exist";
	result = CgiHandlerFriend::get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());

	file_path = "test/unit_test/HttpResponse/GET/empty_file_for_get_interpreter";
	result = CgiHandlerFriend::get_interpreter(file_path);
	EXPECT_FALSE(result.is_ok());
}
