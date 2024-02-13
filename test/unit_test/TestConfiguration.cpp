#include <dirent.h>
#include <sys/types.h>
#include <deque>
#include <iomanip>
#include <list>
#include <string.h>
#include <set>
#include <vector>

#include "Constant.hpp"
#include "Color.hpp"
#include "FileHandler.hpp"
#include "Tokenizer.hpp"
#include "Parser.hpp"
#include "Server.hpp"
#include "TestParser.hpp"
#include "gtest/gtest.h"


TEST(TestConf, ConfigurationOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Configuration config(itr->c_str());

        Result<int, std::string> result = config.get_result();
        // print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestConf, ConfigurationNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_configuration");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Configuration config(itr->c_str());

        Result<int, std::string> result = config.get_result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}
