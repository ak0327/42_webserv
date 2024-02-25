#include <sstream>
#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "HttpResponse.hpp"
#include "TestHttpResponse.hpp"
#include "Result.hpp"


TEST(HttpResponsePOST, IsUrlEncodedForm) {
    std::string request_line = "GET /index.html HTTP/1.1\r\n"
                                     "Host: example.com\r\n"
                                     "Content-Type: application/x-www-form-urlencoded\r\n"
                                     "\r\n";
    HttpRequest request1(request_line);
    bool has_field_name;
    std::string field_name = std::string(CONTENT_TYPE);

    has_field_name = request1.is_valid_field_name_registered(field_name);
    ASSERT_TRUE(has_field_name);

    ServerConfig config;
    AddressPortPair pair;
    HttpResponse response1(request1, config, pair);

    bool result = HttpResponseFriend::is_urlencoded_form_data(response1);
    EXPECT_TRUE(result);

    // -------------------------------------------------------------------------

    request_line = "GET /index.html HTTP/1.1\r\n"
                                     "Host: example.com\r\n"
                                     "Content-Type: multipart/x-www-form-urlencoded\r\n"
                                     "\r\n";
    HttpRequest request2(request_line);
    has_field_name = request2.is_valid_field_name_registered(field_name);
    ASSERT_TRUE(has_field_name);

    HttpResponse response2(request2, config, pair);

    result = HttpResponseFriend::is_urlencoded_form_data(response2);
    EXPECT_FALSE(result);
}


TEST(HttpResponsePOST, IsMultipartForm) {
    std::string request_line = "GET /index.html HTTP/1.1\r\n"
                               "Host: example.com\r\n"
                               "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOzc5oS6JxLwBcmay\r\n"
                               "\r\n";
    HttpRequest request1(request_line);
    bool has_field_name;
    std::string field_name = std::string(CONTENT_TYPE);

    has_field_name = request1.is_valid_field_name_registered(field_name);
    ASSERT_TRUE(has_field_name);

    ServerConfig config;
    AddressPortPair pair;
    HttpResponse response1(request1, config, pair);

    bool result = HttpResponseFriend::is_multipart_form_data(response1);
    EXPECT_TRUE(result);

    // -------------------------------------------------------------------------

    request_line = "GET /index.html HTTP/1.1\r\n"
                   "Host: example.com\r\n"
                   "Content-Type: multipart/form-data\r\n"
                   "\r\n";
    HttpRequest request2(request_line);
    has_field_name = request2.is_valid_field_name_registered(field_name);
    ASSERT_TRUE(has_field_name);

    HttpResponse response2(request2, config, pair);

    result = HttpResponseFriend::is_multipart_form_data(response2);
    EXPECT_FALSE(result);

    // -------------------------------------------------------------------------

    request_line = "GET /index.html HTTP/1.1\r\n"
                   "Host: example.com\r\n"
                   "Content-Type: multipart/form-data; a=b; c=d\r\n"
                   "\r\n";
    HttpRequest request3(request_line);
    has_field_name = request3.is_valid_field_name_registered(field_name);
    ASSERT_TRUE(has_field_name);

    HttpResponse response3(request3, config, pair);

    result = HttpResponseFriend::is_multipart_form_data(response3);
    EXPECT_FALSE(result);
}
