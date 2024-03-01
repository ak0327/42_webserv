#pragma once

#include <list>
#include <vector>
#include "CgiHandler.hpp"
#include "Constant.hpp"
#include "HttpResponse.hpp"
#include "gtest/gtest.h"


class CgiHandlerFriend : public ::testing::Test {
 public:
    static Result<std::vector<std::string>, ProcResult> get_interpreter(const std::string &file_path) {
        return CgiHandler::get_interpreter(file_path);
    }

};
