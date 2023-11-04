#include <sstream>
#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "HttpResponse.hpp"

TEST(HttpResponseGet, CGIHelloPy) {
	const std::string expected_content = "hello" CRLF;
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";
	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << "Content-Type: text/html" << CRLF;
	oss << CRLF;
	oss << expected_content;


	std::string request_target = "cgi-bin/hello.py";
	HttpRequest request("GET", request_target);
	Config config;
	config.set_autoindex(false);
	HttpResponse response(request, config);


	// now: just print for check body
	std::cerr << CYAN << response.get_response_message() << RESET << std::endl;
	// EXPECT_EQ(expected_content, response.get_response_message());
}

TEST(HttpResponseGet, CGIPagepy) {
	const std::string expected_content =
			"<html>" CRLF
			" <head><title>CGI Test Page</title></head>" CRLF
			" <body>" CRLF
			"  <center><h1>CGI Test Page by Python</h1></center>" CRLF
			" </body>" CRLF
			"</html>";
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";
	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << "Content-Type: text/html" << CRLF;
	oss << CRLF;
	oss << expected_content;


	std::string request_target = "cgi-bin/page.py";
	HttpRequest request("GET", request_target);
	Config config;
	config.set_autoindex(false);

	HttpResponse response(request, config);

	// now: just print for check body
	std::cerr << CYAN << response.get_response_message() << RESET << std::endl;
	// EXPECT_EQ(expected_content, response.get_response_message());
}

TEST(HttpResponseGet, CGIPagePhp) {
	const std::string expected_content =
			"<html>" CRLF
			" <head><title>CGI Test Page</title></head>" CRLF
			" <body>" CRLF
			"  <center><h1>CGI Test Page by PHP</h1></center>" CRLF
			" </body>" CRLF
			"</html>";
	const std::size_t expected_content_len = expected_content.length();
	const std::string expected_status_line = "HTTP/1.1 200 OK";
	std::ostringstream oss;
	oss << expected_status_line << CRLF;
	oss << "Content-Length: " << expected_content_len << CRLF;
	oss << "Content-Type: text/html" << CRLF;
	oss << CRLF;
	oss << expected_content;


	std::string request_target = "cgi-bin/page.php";
	HttpRequest request("GET", request_target);
	Config config;
	config.set_autoindex(false);

	HttpResponse response(request, config);

	// now: just print for check body
	std::cerr << CYAN << response.get_response_message() << RESET << std::endl;
	// EXPECT_EQ(expected_content, response.get_response_message());
}
