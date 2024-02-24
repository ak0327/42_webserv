#pragma once

#include <list>
#include <vector>
#include "Constant.hpp"
#include "HttpResponse.hpp"
#include "gtest/gtest.h"


class HttpResponseFriend : public ::testing::Test {
 public:
    static std::string get_resource_path(HttpResponse &response) {
        return response.get_resource_path();
    }

    static std::string get_indexed_path(HttpResponse &response,
                                        const std::string &resource_path) {
        return response.get_indexed_path(resource_path);
    }





    static StatusCode get_request_body(HttpResponse &response,
                                       const std::string &resource_path) {
        return response.get_request_body(resource_path);
    }
};
