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

    static void trim(std::vector<unsigned char> *buf, std::vector<unsigned char>::const_iterator start) {
        return HttpRequest::trim(buf, start);
    }

    static void find_crlf(const std::vector<unsigned char> &data,
                          std::vector<unsigned char>::const_iterator start,
                          std::vector<unsigned char>::const_iterator *cr) {
        return HttpRequest::find_crlf(data, start, cr);
    }

    static void find_empty(const std::vector<unsigned char> &data,
                           std::vector<unsigned char>::const_iterator start,
                           std::vector<unsigned char>::const_iterator *ret) {
        return HttpRequest::find_empty(data, start, ret);
    }
};
