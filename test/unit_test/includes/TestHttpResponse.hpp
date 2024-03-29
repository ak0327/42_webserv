#pragma once

#include <list>
#include <vector>
#include "Constant.hpp"
#include "HttpResponse.hpp"
#include "gtest/gtest.h"


class HttpResponseFriend : public ::testing::Test {
 public:
    // GET
    static std::string get_rooted_path(HttpResponse &response) {
        return response.get_rooted_path();
    }

    static StatusCode get_request_body(HttpResponse &response) {
        return response.get_request_body();
    }


    // POST
    static bool is_urlencoded_form_data(HttpResponse &response) {
        return response.is_urlencoded_form_data();
    }

    static bool is_multipart_form_data(HttpResponse &response, std::string *boundary) {
        return response.is_multipart_form_data(boundary);
    }
};
