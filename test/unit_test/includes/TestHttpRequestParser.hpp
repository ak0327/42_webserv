#pragma once

#include <list>
#include <vector>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "gtest/gtest.h"

class HttpRequestFriend : public ::testing::Test {
 public:
    static Result<std::string, std::string> get_line(const std::vector<unsigned char> &data,
                                                     std::vector<unsigned char>::const_iterator start,
                                                     std::vector<unsigned char>::const_iterator *ret) {
        return HttpRequest::get_line(data, start, ret);
    }


};
