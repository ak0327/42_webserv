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


TEST(TestConfig, ConfigurationOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Configuration config(itr->c_str());

        Result<int, std::string> result = config.get_result();
        // print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestConfig, ConfigurationNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_configuration");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Configuration config(itr->c_str());

        Result<int, std::string> result = config.get_result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}


template <typename Result, typename Value>
void expect_eq_getter(const ServerConfig &server_config,
                      const std::string &location_path,
                      bool expected_error,
                      Value expected,
                      Result (*getter)(const ServerConfig &, const std::string &),
                      int line) {

    Result result = getter(server_config, location_path);
    if (expected_error) {
        ASSERT_TRUE(result.is_err()) << "  at L" << line;
    } else {
        ASSERT_TRUE(result.is_ok()) << "  at L" << line;
        Value actual = result.get_ok_value();

        EXPECT_EQ(expected, actual) << "  at L" << line;;
    }
}


void expect_eq_method(const ServerConfig &server_config,
                      const std::string &location_path,
                      bool expected_error,
                      const std::map<Method, bool> &expected,
                      int line) {
    // std::cout << CYAN << "method" << RESET << std::endl;
    for (std::map<Method, bool>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        Result<bool, int> result = Configuration::is_method_allowed(
                server_config, location_path, itr->first);
        if (expected_error) {
            ASSERT_TRUE(result.is_err()) << "  at L" << line;
        } else {
            // std::cout << CYAN << " result ok" << RESET << std::endl;
            ASSERT_TRUE(result.is_ok()) << "  at L" << line;

            // std::cout << CYAN << " method: " << itr->first << ", expected: " << itr->second << ", actual: " << result.get_ok_value() << RESET << std::endl;
            EXPECT_EQ(itr->second, result.get_ok_value()) << "  at L" << line;;
        }
    }
}


void expect_eq_redirect(const ServerConfig &server_config,
                        const std::string &location_path,
                        bool expected_error,
                        const ReturnDirective &expected,
                        int line) {
    Result<ReturnDirective, int> result = Configuration::get_redirect(server_config, location_path);

    if (expected_error) {
        ASSERT_TRUE(result.is_err()) << "  at L" << line;
    } else {
        ASSERT_TRUE(result.is_ok()) << "  at L" << line;

        ReturnDirective actual = result.get_ok_value();
        EXPECT_EQ(expected.return_on, actual.return_on) << "  at L" << line;;
        EXPECT_EQ(expected.code, actual.code) << "  at L" << line;;
        EXPECT_EQ(expected.text, actual.text) << "  at L" << line;;
    }
}


TEST(TestConfig, ConfigurationGetterOK1) {
    Result<int, std::string> result;
    Configuration config("test/test_conf/ok/parse_ok1.conf");

    std::string server_name, address, port, location_path;

    std::string expected_root, expected_index, expected_error_page;
    bool expected_autoindex, expected_is_redirect;
    bool expected_error;
    std::size_t expected_max_body_size;
    ReturnDirective expected_redirect;
    std::map<Method, bool> expected_method;

    std::string actual_error_page;
    ReturnDirective actual_redirect;

    Result<std::string, int> error_page_result;
    Result<ReturnDirective, int> redirect_result;
    Result<bool, int> method_result;

    ServerConfig server_config;
    Result<ServerConfig, int> server_config_result;

    result = config.get_result();

    // print_error_msg(result, __LINE__);
    ASSERT_TRUE(result.is_ok());


    server_name = "webserv";
    address = "*";
    port = "8080";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    ASSERT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "=/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());





    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());





    // -------------------------------------------------------------------------

    server_name = "server1";
    address = "*";
    port = "8080";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();


    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "=/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());





    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());




    // -------------------------------------------------------------------------


    server_name = "server_nothing";  // same as default_server; webserv and server1
    address = "*";
    port = "8080";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();


    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "=/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());





    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = 301;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    // -------------------------------------------------------------------------

    server_name = "server_nothing";
    address = "*";
    port = "81";  // ng

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_err());  // error

}


TEST(TestConfig, ConfigurationGetterOK2) {
    Result<int, std::string> result;
    Configuration config("test/test_conf/ok/conf_ok1.conf");

    std::string server_name, address, port, location_path;

    std::string expected_root, expected_index, expected_error_page;
    bool expected_autoindex, expected_is_redirect;
    bool expected_error;
    std::size_t expected_max_body_size;
    ReturnDirective expected_redirect;
    std::map<Method, bool> expected_method;

    std::string actual_error_page;
    ReturnDirective actual_redirect;

    Result<std::string, int> error_page_result;
    Result<ReturnDirective, int> redirect_result;
    Result<bool, int> method_result;

    ServerConfig server_config;
    Result<ServerConfig, int> server_config_result;

    result = config.get_result();

    // print_error_msg(result, __LINE__);
    ASSERT_TRUE(result.is_ok());


    server_name = "a";
    address = "*";
    port = "81";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_a";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);




    location_path = "b";
    expected_error = true;  // error

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);



    location_path = "c";
    expected_error = true;  // error

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    // -------------------------------------------------------------------------


    server_name = "c";
    address = "*";
    port = "81";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);




    location_path = "b";
    expected_error = true;  // error

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);



    location_path = "c";
    expected_error = true;  // error

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    // -------------------------------------------------------------------------

    server_name = "nothing";  // same as server c
    address = "*";
    port = "81";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);




    location_path = "b";
    expected_error = true;  // error

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);



    location_path = "c";
    expected_error = true;  // error

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Configuration::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Configuration::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Configuration::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Configuration::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Configuration::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    // -------------------------------------------------------------------------

    server_name = "a";
    address = "*";
    port = "8080";  // nothing -> can't get server_config

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_err());  // nothing
}
