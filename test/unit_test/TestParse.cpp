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


std::set<std::string> get_conf_files(const std::string &directory_path) {
    std::set<std::string> conf_files;
    DIR *dir = opendir(directory_path.c_str());
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_REG) {
                std::string file_name = entry->d_name;
                if (file_name.size() > 5 && file_name.substr(file_name.size() - 5) == ".conf") {
                    std::string path = directory_path;
                    path.append("/");
                    path.append(file_name);
                    conf_files.insert(path);
                }
            }
        }
        closedir(dir);
    }
    return conf_files;
}


TEST(TestParser, ParseOK) {
    HttpConfig expected, actual;
    ServerConfig server_config;
    LocationConfig location_config;
    Result<int, std::string> result;
    ListenDirective listen;

    Parser parser1("test/test_conf/ok/parse_ok1.conf");

    expected = {};

    server_config = {};
    listen = {};
    listen = ListenDirective(ConfigInitValue::kDefaultAddress, "8080", false);
    server_config.listens.push_back(listen);

    server_config.server_names.insert("webserv");
    server_config.server_names.insert("server1");

    server_config.root_path = "www";

    server_config.error_pages = {
            {NotFound               , "/404.html"},
            {InternalServerError    , "/50x.html"},
            {BadGateway             , "/50x.html"},
            {ServiceUnavailable     , "/50x.html"},
            {GatewayTimeout         , "/50x.html"},
    };

    // location "/"
    location_config = LocationConfig(server_config);
    location_config.root_path = "html";
    location_config.index_pages = {"index.html", "index.htm"};
    server_config.locations["/"] = location_config;

    // location "/old.html"
    location_config = LocationConfig(server_config);
    location_config.redirection.return_on = true;
    location_config.redirection.code = MovedPermanently;
    location_config.redirection.text = "/new.html";
    server_config.locations["/old.html"] = location_config;

    // location "/upload"
    location_config = LocationConfig(server_config);
    location_config.autoindex = true;
    server_config.locations["/upload"] = location_config;

    // location "/post"
    location_config = LocationConfig(server_config);
    location_config.limit_except.excluded_methods = {kPOST, kDELETE};
    location_config.limit_except.rules.push_back(AccessRule(kDENY, "all"));
    location_config.max_body_size_bytes = 20 * ConfigInitValue::MB;
    location_config.root_path = "/upload";
    server_config.locations["/post"] = location_config;

    location_config = LocationConfig(server_config);
    location_config.root_path = "www";
    server_config.locations["=/50x.html"] = location_config;

    expected.servers.push_back(server_config);

    actual = parser1.config();
    result = parser1.result();

    // print_error_msg(result, __LINE__);
    EXPECT_TRUE(result.is_ok());
    expect_eq_http_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    Parser parser2("test/test_conf/ok/parse_ok2.conf");

    expected = {};

    server_config = {};
    listen = ListenDirective(ConfigInitValue::kDefaultAddress, "8484", true);
    server_config.listens.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "4242", false));
    server_config.listens.push_back(listen);

    server_config.server_names.insert("cgi_server");

    server_config.root_path = "www";

    location_config = LocationConfig(server_config);
    server_config.locations["^~/cgi-bin/"] = location_config;

    expected.servers.push_back(server_config);

    actual = parser2.config();
    result = parser2.result();

    // print_error_msg(result, __LINE__);
    EXPECT_TRUE(result.is_ok());
    expect_eq_http_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    Parser parser3("test/test_conf/ok/parse_ok3.conf");

    expected = {};

    server_config = {};
    listen = ListenDirective(ConfigInitValue::kDefaultAddress, "8080", false);
    server_config.listens.push_back(listen);

    server_config.server_names.insert("webserv");
    server_config.server_names.insert("server1");

    server_config.root_path = "www";

    server_config.error_pages = {
            {NotFound               , "/404.html"},
            {InternalServerError    , "/50x.html"},
            {BadGateway             , "/50x.html"},
            {ServiceUnavailable     , "/50x.html"},
            {GatewayTimeout         , "/50x.html"},
    };

    location_config = LocationConfig(server_config);
    location_config.root_path = "html";
    location_config.index_pages = {"index.html", "index.htm"};
    server_config.locations["/"] = location_config;

    location_config = LocationConfig(server_config);
    location_config.redirection.return_on = true;
    location_config.redirection.code = MovedPermanently;
    location_config.redirection.text = "/new.html";
    server_config.locations["/old.html"] = location_config;

    location_config = LocationConfig(server_config);
    location_config.autoindex = true;
    server_config.locations["/upload"] = location_config;

    location_config = LocationConfig(server_config);
    location_config.limit_except.excluded_methods = {kPOST, kDELETE};
    location_config.limit_except.rules.push_back(AccessRule(kDENY, "all"));
    location_config.max_body_size_bytes = 20 * ConfigInitValue::MB;
    location_config.root_path = "/upload";
    server_config.locations["/post"] = location_config;

    location_config = LocationConfig(server_config);
    location_config.root_path = "www";
    server_config.locations["=/50x.html"] = location_config;

    expected.servers.push_back(server_config);



    server_config = {};
    ListenDirective listen2 = ListenDirective(ConfigInitValue::kDefaultAddress, "8484", true);
    server_config.listens.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "4242", false));
    server_config.listens.push_back(listen2);

    server_config.server_names.insert("cgi_server");

    server_config.root_path = "www";

    location_config = LocationConfig(server_config);
    server_config.locations["^~/cgi-bin/"] = location_config;

    expected.servers.push_back(server_config);

    actual = parser3.config();
    result = parser3.result();

    // print_error_msg(result, __LINE__);
    EXPECT_TRUE(result.is_ok());
    expect_eq_http_config(expected, actual, __LINE__);
}


TEST(TestParser, ParseHttpBlockOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok/ok_http_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());
        Result<int, std::string> result = parser.result();
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestParser, ParseHttpBlockNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_http_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());

        Result<int, std::string> result = parser.result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}


TEST(TestParser, ParseServerBlockOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok/ok_server_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());
        Result<int, std::string> result = parser.result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestParser, ParseServerBlockNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_server_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());

        Result<int, std::string> result = parser.result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}


TEST(TestParser, ParseLocationBlockOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok/ok_location_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());
        Result<int, std::string> result = parser.result();
        // print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestParser, ParseLocationBlockNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_location_block");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Parser parser(itr->c_str());

        Result<int, std::string> result = parser.result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}
