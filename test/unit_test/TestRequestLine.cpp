#include "Color.hpp"
#include "Constant.hpp"
#include "RequestLine.hpp"
#include "gtest/gtest.h"

/* RequestLine passed line; getline(line, LF), from HttpRequest */
/* so, RequestLine parses end with CR line */
TEST(TestRequestLine, RequestLineOK1) {
	const std::string request_line = "GET /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, RequestLineOK2) {
	const std::string request_line = "POST /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("POST", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, RequestLineOK3) {
	const std::string request_line = "DELETE /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("DELETE", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, RequestLineOK4) {
	const std::string request_line = "GET /index.html?hoge? HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_EQ("hoge?", request.query());
	EXPECT_TRUE(result.is_ok());
}

TEST(TestRequestLine, RequestLineOK5) {
    const std::string request_line = "GET /path?key1=value1&key2=value2 HTTP/1.1";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("/path", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_EQ("key1=value1&key2=value2", request.query());
    EXPECT_TRUE(result.is_ok());
}


////////////////////////////////////////////////////////////////////////////////

TEST(TestRequestLine, RequestLineNG1) {
	const std::string request_line = "GET /index.html HTTP/1.1 ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG2) {
	const std::string request_line = "GET /index.html HTTP/1.1\n";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG3) {
	const std::string request_line = "GET /index.html HTTP/1.1\r ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG4) {
	const std::string request_line = "";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG5) {
	const std::string request_line = " ";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG6) {
	const std::string request_line = "";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("", request.method());
	EXPECT_EQ("", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG7) {
	const std::string request_line = "get /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("get", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG8) {
	const std::string request_line = "delete /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("delete", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG9) {
	const std::string request_line = "GET /index.html HTTP/1.0";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG10) {
	const std::string request_line = "GET /index.html HTTP/1.12";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG11) {
	const std::string request_line = "GET /index.html http/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG12) {
	const std::string request_line = "GET \n/index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("\n/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG13) {
	const std::string request_line = "GET /index.html\nHTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG14) {
	const std::string request_line = "HEAD /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("HEAD", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG15) {
	const std::string request_line = "OPTIONS /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("OPTIONS", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG16) {
	const std::string request_line = "PUT /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("PUT", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG17) {
	const std::string request_line = "TRACE /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("TRACE", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG18) {
	const std::string request_line = "CONNECT /index.html HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("CONNECT", request.method());
	EXPECT_EQ("/index.html", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG19) {
	const std::string request_line = "GET '/index.html' HTTP/1.1";
	RequestLine request;
	Result<ProcResult, StatusCode> result;

	result = request.parse_and_validate(request_line);
	EXPECT_EQ("GET", request.method());
	EXPECT_EQ("'/index.html'", request.target());
	EXPECT_EQ("HTTP/1.1", request.http_version());
	EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG20) {
    const std::string request_line = "GET / HTTP/1.1\r";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("/", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG21) {
    const std::string request_line = "GET . HTTP/1.1";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ(".", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG22) {
    const std::string request_line = "GET - HTTP/1.1";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("-", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());
}

TEST(TestRequestLine, RequestLineNG23) {
    const std::string request_line = "GET /index.html HTTP/2.0";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("/index.html", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());  // update
}

TEST(TestRequestLine, RequestLineNG24) {
    const std::string request_line = "GET /index.html HTTP/3.0";
    RequestLine request;
    Result<ProcResult, StatusCode> result;

    result = request.parse_and_validate(request_line);
    EXPECT_EQ("GET", request.method());
    EXPECT_EQ("/index.html", request.target());
    EXPECT_EQ("HTTP/1.1", request.http_version());
    EXPECT_TRUE(result.is_err());  // update
}
