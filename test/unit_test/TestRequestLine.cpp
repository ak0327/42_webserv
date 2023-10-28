#include "Color.hpp"
#include "Constant.hpp"
#include "RequestLine.hpp"
#include "gtest/gtest.h"

/* RequestLine passed line; getline(line, LF), from HttpRequest */
/* so, RequestLine parses end with CR line */
TEST(TestRequestLine, ResuestLineOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK2) {
	const std::string request_line = "POST /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("POST", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK3) {
	const std::string request_line = "DELETE /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("DELETE", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK4) {
	const std::string request_line = "GET /index.html HTTP/2.0\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/2.0", request.get_http_version());
	EXPECT_EQ(true, result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK5) {
	const std::string request_line = "GET /index.html HTTP/3.0\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/3.0", request.get_http_version());
	EXPECT_EQ(true, result.is_ok());
}



TEST(TestRequestLine, ResuestLineNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1 \r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1 ", request.get_http_version());  // todo: space
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\n";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r ";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG4) {
	const std::string request_line = "";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.get_method());
	EXPECT_EQ("", request.get_request_target());
	EXPECT_EQ("", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG5) {
	const std::string request_line = " ";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.get_method());
	EXPECT_EQ("", request.get_request_target());
	EXPECT_EQ("", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG6) {
	const std::string request_line = "\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.get_method());
	EXPECT_EQ("", request.get_request_target());
	EXPECT_EQ("", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG7) {
	const std::string request_line = "get /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("get", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG8) {
	const std::string request_line = "delete /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("delete", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG9) {
	const std::string request_line = "GET /index.html HTTP/1.0\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.0", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG10) {
	const std::string request_line = "GET /index.html HTTP/1.12\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.12", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG11) {
	const std::string request_line = "GET /index.html http/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("http/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG12) {
	const std::string request_line = "GET \n/index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("\n/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG13) {
	const std::string request_line = "GET /index.html\nHTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("", request.get_request_target());
	EXPECT_EQ("", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG14) {
	const std::string request_line = "HEAD /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("HEAD", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG15) {
	const std::string request_line = "OPTIONS /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("OPTIONS", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG16) {
	const std::string request_line = "PUT /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("PUT", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG17) {
	const std::string request_line = "TRACE /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("TRACE", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}

TEST(TestRequestLine, ResuestLineNG18) {
	const std::string request_line = "CONNECT /index.html HTTP/1.1\r";
	RequestLine request;
	Result<int, int> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("CONNECT", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(true, result.is_err());
}
