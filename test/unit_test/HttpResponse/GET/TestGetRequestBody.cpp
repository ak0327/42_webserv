#include <sstream>
#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Config.hpp"
#include "HttpResponse.hpp"
#include "TestHttpResponse.hpp"
#include "Result.hpp"

#define EXPECT_EQ_TARGET(conf, request_msg, expected) expect_eq_target(conf, request_msg, expected, __LINE__);

void expect_eq_target(const ServerConfig &server_config,
                      const std::string &request_msg,
                      const std::string &expected_path,
                      std::size_t line) {
    HttpRequest request(request_msg);
    HttpResponse response(request, server_config);

    std::string actual_path = HttpResponseFriend::get_resource_path(response);
    EXPECT_EQ(expected_path, actual_path) << "  at L" << line;
}


TEST(HttpResponseGET, GetResourcePath) {
    Config config("test/test_conf/ok/test_request_body.conf");
    std::string server_name = "localhost";
    std::string address = "*";
    std::string port = "4242";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    Result<ServerConfig, int> server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    ServerConfig server_config = server_config_result.get_ok_value();

    std::string request_msg, expected_path;
    request_msg = "GET / HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);

    request_msg = "GET // HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /// HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /../../../././././ HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /index.html HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/index.html";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /index.html HTTP/1.1\r\n"
                  "Host: hoge\r\n"
                  "\r\n";
    expected_path = "html/index.html";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /dir_a HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/dir_a/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /dir_a/ HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/dir_a/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /a/b HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/b/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /a/b/c HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/b/c/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /a/b/.//.. HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /a/b/.//../c HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/c/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /nothing HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/nothing/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /nothing.html HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/nothing.html";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /old.html HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/old.html";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /autoindex_files/ HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/autoindex_files/";  // todo: ok?
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);


    request_msg = "GET /autoindex_files HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/autoindex_files/";
    EXPECT_EQ_TARGET(server_config, request_msg, expected_path);
}



#define EXPECT_EQ_INDEXED_PATH(conf, request_msg, expected) expect_eq_indexed_path(conf, request_msg, expected, __LINE__);

void expect_eq_indexed_path(const ServerConfig &server_config,
                      const std::string &request_msg,
                      const std::string &expected_path,
                      std::size_t line) {
    HttpRequest request(request_msg);
    HttpResponse response(request, server_config);

    std::string resource_path = HttpResponseFriend::get_resource_path(response);
    std::string actual_path = HttpResponseFriend::get_indexed_path(response, resource_path);
    EXPECT_EQ(expected_path, actual_path) << "  at L" << line;
}


TEST(HttpResponseGET, GetFilePath) {
    Config config("test/test_conf/ok/test_request_body.conf");
    std::string server_name = "localhost";
    std::string address = "*";
    std::string port = "4242";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    Result<ServerConfig, int> server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    ServerConfig server_config = server_config_result.get_ok_value();

    std::string request_msg, expected_path;

    request_msg = "GET / HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/index.html";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /index.html HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/index.html";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /../.././././../ HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/index.html";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /a/b HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/b/file_b.html";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /a/b/c HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/a/b/c/index.html";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /autoindex_files/ HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/autoindex_files/";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);


    request_msg = "GET /autoindex_files HTTP/1.1\r\n"
                  "Host: localhost\r\n"
                  "\r\n";
    expected_path = "html/autoindex_files/";
    EXPECT_EQ_INDEXED_PATH(server_config, request_msg, expected_path);

}

//
// #define EXPECT_EQ_BODY(file_path, actual_body) expect_eq_body(file_path, actual_body, __LINE__);
//
// void expect_eq_body(const std::string &expected_file_path,
//                     const std::vector<unsigned char> &actual_body,
//                     std::size_t line) {
//
//
//
//
// }
//
//
// TEST(HttpResponseGET, GetReqestBody1) {
//     HttpRequest request;
//     ServerConfig server_config;
//
//     Config config("test/test_conf/ok/test_request_body.conf");
//     std::string server_name = "localhost";
//     std::string address = "*";
//     std::string port = "4242";
//
//     ServerInfo server_info = ServerInfo(server_name, address, port);
//     Result<ServerConfig, int> server_config_result = config.get_server_config(server_info);
//     ASSERT_TRUE(server_config_result.is_ok());
//     ServerConfig server_config = server_config_result.get_ok_value();
//
//     HttpResponse response(request, server_config);
//     std::string target = "/";
//
//     Result<ProcResult, StatusCode> result = HttpResponseFriend::get_request_body(response, target);
//     ASSERT_TRUE(result.is_ok());
//
//     std::string expected_file = "index.html";
//     EXPECT_EQ_BODY(expected_file, response.body_buf());
//
//
// }
//
// TEST(HttpResponseGET, GetReqestBodySlash) {
// 	const std::string expected_content = "<!doctype html>\n"
// 										 "<html lang=\"ja\">\n"
// 										 "<head>\n"
// 										 "    <meta charset=\"UTF-8\">\n"
// 										 "    <title>Test Server</title>\n"
// 										 "    <link rel=\"stylesheet\" href=\"index.css\">\n"
// 										 "</head>\n"
// 										 "<body>\n"
// 										 "<h1>Webserv test page</h1>\n"
// 										 "<img alt=\"image\" src=\"images/image2.jpeg\">\n"
// 										 "<h2>hello world</h2>\n"
// 										 "<h3>hoge</h3>\n"
// 										 "<h4>huga</h4>\n"
// 										 "<h5>piyo</h5>\n"
// 										 "\n"
// 										 "<br>\n"
// 										 "<a href=\"form.html\">form.html</a>\n"
// 										 "<br>\n"
// 										 "<br>\n"
// 										 "<a href=\"/login\">login endpoint</a>\n"
// 										 "<br>\n"
// 										 "<br>\n"
// 										 "\n"
// 										 "</body>\n"
// 										 "</html>";
// 	const std::size_t expected_content_len = expected_content.length();
// 	const std::string expected_status_line = "HTTP/1.1 200 OK";
//
// 	std::ostringstream oss;
// 	oss << expected_status_line << CRLF;
// 	oss << "Content-Length: " << expected_content_len << CRLF;
// 	oss << CRLF;
// 	oss << expected_content;
//
// 	const std::string expected_response_message = oss.str();
//
// 	std::string request_target = "/";
// 	HttpRequest request("GET", request_target);
// 	Config config;
//
// 	HttpResponse response(request, config);
//
// 	EXPECT_EQ(expected_response_message, response.get_response_message());
// }
//
// TEST(HttpResponseGET, GetReqestBodyIndexHtml) {
// 	const std::string expected_content = "<!doctype html>\n"
// 										 "<html lang=\"ja\">\n"
// 										 "<head>\n"
// 										 "    <meta charset=\"UTF-8\">\n"
// 										 "    <title>Test Server</title>\n"
// 										 "    <link rel=\"stylesheet\" href=\"index.css\">\n"
// 										 "</head>\n"
// 										 "<body>\n"
// 										 "<h1>Webserv test page</h1>\n"
// 										 "<img alt=\"image\" src=\"images/image2.jpeg\">\n"
// 										 "<h2>hello world</h2>\n"
// 										 "<h3>hoge</h3>\n"
// 										 "<h4>huga</h4>\n"
// 										 "<h5>piyo</h5>\n"
// 										 "\n"
// 										 "<br>\n"
// 										 "<a href=\"form.html\">form.html</a>\n"
// 										 "<br>\n"
// 										 "<br>\n"
// 										 "<a href=\"/login\">login endpoint</a>\n"
// 										 "<br>\n"
// 										 "<br>\n"
// 										 "\n"
// 										 "</body>\n"
// 										 "</html>";
// 	const std::size_t expected_content_len = expected_content.length();
// 	const std::string expected_status_line = "HTTP/1.1 200 OK";
//
// 	std::ostringstream oss;
// 	oss << expected_status_line << CRLF;
// 	oss << "Content-Length: " << expected_content_len << CRLF;
// 	oss << CRLF;
// 	oss << expected_content;
//
// 	const std::string expected_response_message = oss.str();
//
// 	std::string request_target = "index.html";
// 	HttpRequest request("GET", request_target);
// 	Config config;
//
// 	HttpResponse response(request, config);
//
// 	EXPECT_EQ(expected_response_message, response.get_response_message());
// }
//
// TEST(HttpResponseGET, GetReqestBodyIndexCss) {
// 	const std::string expected_content = "h2 {\n"
// 										 "    color: red;\n"
// 										 "}\n"
// 										 "\n"
// 										 "h3 {\n"
// 										 "    color: blue;\n"
// 										 "}\n"
// 										 "\n"
// 										 "h5 {\n"
// 										 "    color: yellow;\n"
// 										 "}";
// 	const std::size_t expected_content_len = expected_content.length();
// 	const std::string expected_status_line = "HTTP/1.1 200 OK";
//
// 	std::ostringstream oss;
// 	oss << expected_status_line << CRLF;
// 	oss << "Content-Length: " << expected_content_len << CRLF;
// 	oss << CRLF;
// 	oss << expected_content;
//
// 	const std::string expected_response_message = oss.str();
//
// 	std::string request_target = "index.css";
// 	HttpRequest request("GET", request_target);
// 	Config config;
//
// 	HttpResponse response(request, config);
//
// 	EXPECT_EQ(expected_response_message, response.get_response_message());
// }
//
// TEST(HttpResponseGET, GetReqestBody404) {
// 	const std::string expected_content = std::string(error_404_page);
// 	const std::size_t expected_content_len = expected_content.length();
// 	const std::string expected_status_line = "HTTP/1.1 404 Not Found";
//
// 	std::ostringstream oss;
// 	oss << expected_status_line << CRLF;
// 	oss << "Content-Length: " << expected_content_len << CRLF;
// 	oss << CRLF;
// 	oss << expected_content;
//
// 	const std::string expected_response_message = oss.str();
//
// 	std::string request_target = "/no_such_file.html";
// 	HttpRequest request("GET", request_target);
//
// 	Config config;
//
// 	HttpResponse response(request, config);
//
// 	EXPECT_EQ(expected_response_message, response.get_response_message());
// }
//
// TEST(HttpResponseGET, GetReqestBody406) {
// 	const std::string expected_content = std::string(error_406_page);
// 	const std::size_t expected_content_len = expected_content.length();
// 	const std::string expected_status_line = "HTTP/1.1 406 Not Acceptable";
//
// 	std::ostringstream oss;
// 	oss << expected_status_line << CRLF;
// 	oss << "Content-Length: " << expected_content_len << CRLF;
// 	oss << CRLF;
// 	oss << expected_content;
//
// 	const std::string expected_response_message = oss.str();
//
// 	std::string request_target = "/no_such_file.xxxx";
// 	HttpRequest request("GET", request_target);
//
// 	Config config;
//
// 	HttpResponse response(request, config);
//
// 	EXPECT_EQ(expected_response_message, response.get_response_message());
// }
