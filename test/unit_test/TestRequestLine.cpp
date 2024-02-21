#include "Color.hpp"
#include "Constant.hpp"
#include "RequestLine.hpp"
#include "gtest/gtest.h"

/* RequestLine passed line; getline(line, LF), from HttpRequest */
/* so, RequestLine parses end with CR line */
TEST(TestRequestLine, ResuestLineOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK2) {
	const std::string request_line = "POST /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("POST", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK3) {
	const std::string request_line = "DELETE /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("DELETE", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK4) {
	const std::string request_line = "GET /index.html HTTP/2.0";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/2.0", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK5) {
	const std::string request_line = "GET /index.html HTTP/3.0";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/3.0", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, ResuestLineOK6) {
	const std::string request_line = "GET /index.html?hoge? HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html?hoge?", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

////////////////////////////////////////////////////////////////////////////////

TEST(TestRequestLine, ResuestLineNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1 ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1 ", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\n";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1\n", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1\r ", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG4) {
	const std::string request_line = "";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.request_target());
	EXPECT_EQ("", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG5) {
	const std::string request_line = " ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.request_target());
	EXPECT_EQ("", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG6) {
	const std::string request_line = "";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.request_target());
	EXPECT_EQ("", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG7) {
	const std::string request_line = "get /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("get", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG8) {
	const std::string request_line = "delete /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("delete", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG9) {
	const std::string request_line = "GET /index.html HTTP/1.0";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.0", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG10) {
	const std::string request_line = "GET /index.html HTTP/1.12";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.12", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG11) {
	const std::string request_line = "GET /index.html http/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("http/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG12) {
	const std::string request_line = "GET \n/index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("\n/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG13) {
	const std::string request_line = "GET /index.html\nHTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("", request.request_target());
	EXPECT_EQ("", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG14) {
	const std::string request_line = "HEAD /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("HEAD", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG15) {
	const std::string request_line = "OPTIONS /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("OPTIONS", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG16) {
	const std::string request_line = "PUT /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("PUT", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG17) {
	const std::string request_line = "TRACE /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("TRACE", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG18) {
	const std::string request_line = "CONNECT /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("CONNECT", request.method());
	EXPECT_EQ("/index.html", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG19) {
	const std::string request_line = "GET '/index.html' HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("'/index.html'", request.request_target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG20) {
    const std::string request_line = "GET / HTTP/1.1\r";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("/", request.request_target());
    EXPECT_EQ("HTTP/1.1\r", request.http_version());
    EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG21) {
    const std::string request_line = "GET . HTTP/1.1";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ(".", request.request_target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, ResuestLineNG22) {
    const std::string request_line = "GET - HTTP/1.1";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("-", request.request_target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());
}
