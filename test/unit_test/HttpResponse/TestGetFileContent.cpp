#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

TEST(HttpResponseGET, GetFileContentIndexHtml) {
	const std::string expected_content = "<!doctype html>\n"
										 "<html lang=\"ja\">\n"
										 "<head>\n"
										 "    <meta charset=\"UTF-8\">\n"
										 "    <title>Test Server</title>\n"
										 "    <link rel=\"stylesheet\" href=\"index.css\">\n"
										 "</head>\n"
										 "<body>\n"
										 "<h1>Webserv test page</h1>\n"
										 "<img alt=\"image\" src=\"images/image2.jpeg\">\n"
										 "<h2>hello world</h2>\n"
										 "<h3>hoge</h3>\n"
										 "<h4>huga</h4>\n"
										 "<h5>piyo</h5>\n"
										 "\n"
										 "<br>\n"
										 "<a href=\"form.html\">form.html</a>\n"
										 "<br>\n"
										 "<br>\n"
										 "<a href=\"/login\">login endpoint</a>\n"
										 "<br>\n"
										 "<br>\n"
										 "\n"
										 "</body>\n"
										 "</html>";
	const std::size_t expected_length = expected_content.length();
	Result<std::string, int> result;
	std::string file_path;
	std::size_t content_length;
	Config config;

	file_path = "www/index.html";
	result = get_file_content(file_path, &content_length, config.get_mime_types());
	EXPECT_TRUE(result.is_ok());
	if (result.is_err()) {
		FAIL() << "unexpected result";
	}
	EXPECT_EQ(expected_content, result.get_ok_value());
	EXPECT_EQ(expected_length, content_length);
}

TEST(HttpResponseGET, GetFileContentIndexCss) {
	const std::string expected_content = "h2 {\n"
										 "    color: red;\n"
										 "}\n"
										 "\n"
										 "h3 {\n"
										 "    color: blue;\n"
										 "}\n"
										 "\n"
										 "h5 {\n"
										 "    color: yellow;\n"
										 "}";
	const std::size_t expected_length = expected_content.length();
	Result<std::string, int> result;
	std::string file_path;
	std::size_t content_length;
	Config config;

	file_path = "www/index.css";
	result = get_file_content(file_path, &content_length, config.get_mime_types());
	EXPECT_TRUE(result.is_ok());
	if (result.is_err()) {
		FAIL() << "unexpected result";
	}
	EXPECT_EQ(expected_content, result.get_ok_value());
	EXPECT_EQ(expected_length, content_length);
}

TEST(HttpResponseGET, GetFileContentFileNotExist) {
	const std::size_t expected_length = 0;
	Result<std::string, int> result;
	std::string file_path;
	std::size_t content_length;
	Config config;

	file_path = "hoge";
	result = get_file_content(file_path, &content_length, config.get_mime_types());
	EXPECT_TRUE(result.is_err());
	EXPECT_EQ(expected_length, content_length);
}
