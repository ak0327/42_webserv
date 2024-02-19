#include <sstream>
#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

TEST(HttpResponseGET, GetReqestBodySlash) {
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
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";

	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << CRLF;
	oss << expected_content;

	const std::string expected_response_message = oss.str();

	std::string request_target = "/";
	HttpRequest request("GET", request_target);
	Config config;

	HttpResponse response(request, config);

	EXPECT_EQ(expected_response_message, response.get_response_message());
}

TEST(HttpResponseGET, GetReqestBodyIndexHtml) {
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
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";

	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << CRLF;
	oss << expected_content;

	const std::string expected_response_message = oss.str();

	std::string request_target = "index.html";
	HttpRequest request("GET", request_target);
	Config config;

	HttpResponse response(request, config);

	EXPECT_EQ(expected_response_message, response.get_response_message());
}

TEST(HttpResponseGET, GetReqestBodyIndexCss) {
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
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";

	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << CRLF;
	oss << expected_content;

	const std::string expected_response_message = oss.str();

	std::string request_target = "index.css";
	HttpRequest request("GET", request_target);
	Config config;

	HttpResponse response(request, config);

	EXPECT_EQ(expected_response_message, response.get_response_message());
}

TEST(HttpResponseGET, GetReqestBody404) {
	const std::string expected_content = std::string(error_404_page);
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 404 Not Found";

	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << CRLF;
	oss << expected_content;

	const std::string expected_response_message = oss.str();

	std::string request_target = "/no_such_file.html";
	HttpRequest request("GET", request_target);

	Config config;

	HttpResponse response(request, config);

	EXPECT_EQ(expected_response_message, response.get_response_message());
}

TEST(HttpResponseGET, GetReqestBody406) {
	const std::string expected_content = std::string(error_406_page);
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 406 Not Acceptable";

	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << CRLF;
	oss << expected_content;

	const std::string expected_response_message = oss.str();

	std::string request_target = "/no_such_file.xxxx";
	HttpRequest request("GET", request_target);

	Config config;

	HttpResponse response(request, config);

	EXPECT_EQ(expected_response_message, response.get_response_message());
}
