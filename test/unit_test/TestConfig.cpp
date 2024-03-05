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
#include "ConfigParser.hpp"
#include "Server.hpp"
#include "TestParser.hpp"
#include "gtest/gtest.h"


TEST(TestConfig, ConfigOK) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ok");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Config config(itr->c_str());

        Result<int, std::string> result = config.result();
        // print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_ok());
    }
}


TEST(TestConfig, ConfigNG) {
    std::set<std::string> conf_files = get_conf_files("test/test_conf/ng/ng_configuration");

    for (std::set<std::string>::const_iterator itr = conf_files.begin(); itr != conf_files.end(); ++itr) {
        debug_print("path: " + *itr, __LINE__);

        Config config(itr->c_str());

        Result<int, std::string> result = config.result();
        print_error_msg(result, __LINE__);
        EXPECT_TRUE(result.is_err());
    }
}


TEST(TestConfig, IsExactMatch) {
    bool actual;
    std::string pattern, target;

    pattern = "=/";
    target = "/";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "=/root";
    target = "/root";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "=html";
    target = "html";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "=/50x.html";
    target = "/50x.html";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_TRUE(actual);

    // -------------------------------------------------------------------------

    pattern = "=/";
    target = "/root";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "=/";
    target = "/root";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "";
    target = "";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "=";
    target = "=";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "=/";
    target = "";
    actual = Config::is_exact_match(pattern, target);
    EXPECT_FALSE(actual);
}


TEST(TestConfig, IsPrefixMatch) {
    bool actual;
    std::string pattern, target;

    pattern = "^~/";
    target = "/";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "^~/root";
    target = "/root";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "^~html";
    target = "html";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "^~/";
    target = "/root/hoge/huga";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "^~/images/";
    target = "/images/";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    pattern = "^~/images/";
    target = "/images/aaa/bbb/ccc.html";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_TRUE(actual);

    // -------------------------------------------------------------------------

    pattern = "^~/";
    target = "root";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "^~/";
    target = "html/images";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "";
    target = "";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "^~aaa";
    target = "aa";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_FALSE(actual);

    pattern = "^~";
    target = "";
    actual = Config::is_prefix_match(pattern, target);
    EXPECT_FALSE(actual);
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
        Value actual = result.ok_value();

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
        Result<bool, int> result = Config::is_method_allowed(
                server_config, location_path, itr->first);
        if (expected_error) {
            ASSERT_TRUE(result.is_err()) << "  at L" << line;
        } else {
            // std::cout << CYAN << " result ok" << RESET << std::endl;
            ASSERT_TRUE(result.is_ok()) << "  at L" << line;

            // std::cout << CYAN << " method: " << itr->first << ", expected: " << itr->second << ", actual: " << result.get_ok_value() << RESET << std::endl;
            EXPECT_EQ(itr->second, result.ok_value()) << "  at L" << line;;
        }
    }
}


void expect_eq_redirect(const ServerConfig &server_config,
                        const std::string &location_path,
                        bool expected_error,
                        const ReturnDirective &expected,
                        int line) {
    Result<ReturnDirective, int> result = Config::get_redirect(server_config, location_path);

    if (expected_error) {
        ASSERT_TRUE(result.is_err()) << "  at L" << line;
    } else {
        ASSERT_TRUE(result.is_ok()) << "  at L" << line;

        ReturnDirective actual = result.ok_value();
        EXPECT_EQ(expected.return_on, actual.return_on) << "  at L" << line;;
        EXPECT_EQ(expected.code, actual.code) << "  at L" << line;;
        EXPECT_EQ(expected.text, actual.text) << "  at L" << line;;
    }
}


TEST(TestConfig, ConfigGetterOK1) {
    Result<int, std::string> result;
    Config config("test/test_conf/ok/parse_ok1.conf");

    std::string server_name, address, port, location_path;

    std::string expected_root, expected_index, expected_error_page;
    bool expected_autoindex, expected_is_redirect;
    bool expected_error;

    bool expected_cgi_mode, is_cgi_extension;
    std::set<std::string> expected_cgi_extension;
    time_t expected_cgi_timeout;

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

    result = config.result();

    // print_error_msg(result, __LINE__);
    ASSERT_TRUE(result.is_ok());


    server_name = "webserv";
    address = "*";
    port = "8080";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.ok_value();

    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    ASSERT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());

    expected_cgi_mode = ConfigInitValue::kDefaultRedirectOn;
    expected_cgi_extension = {};
    expected_cgi_timeout = ConfigInitValue::kDefaultCgiTimeoutSec;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    AddressPortPair client_listen("127.0.0.1", "8080");
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/", client_listen, kGET));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/", client_listen, kPOST));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/", client_listen, kDELETE));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/index.html", client_listen, kGET));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/index.html", client_listen, kPOST));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/index.html", client_listen, kDELETE));



    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());

    expected_cgi_mode = ConfigInitValue::kDefaultRedirectOn;
    expected_cgi_extension = {"hello"};
    expected_cgi_timeout = ConfigInitValue::kDefaultCgiTimeoutSec;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());

    expected_cgi_mode = ConfigInitValue::kDefaultRedirectOn;
    expected_cgi_extension = {};
    expected_cgi_timeout = ConfigInitValue::kDefaultCgiTimeoutSec;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());

    expected_cgi_mode = true;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    client_listen = AddressPortPair("127.0.0.1", "8080");
    EXPECT_FALSE(Config::is_method_allowed(server_config, "/post", client_listen, kGET));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/post", client_listen, kPOST));
    EXPECT_TRUE(Config::is_method_allowed(server_config, "/post", client_listen, kDELETE));



    location_path = "/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;

    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/cgi-bin/";
    expected_error = false;
    expected_cgi_mode = true;
    is_cgi_extension = false;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(is_cgi_extension, Config::is_cgi_extension(server_config, location_path));
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    location_path = "/cgi-bin/hello.py";
    expected_cgi_mode = true;
    is_cgi_extension = true;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(is_cgi_extension, Config::is_cgi_extension(server_config, location_path));
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    location_path = "/cgi-bin/hello.php";
    expected_cgi_mode = true;
    is_cgi_extension = true;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(is_cgi_extension, Config::is_cgi_extension(server_config, location_path));
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    location_path = "/cgi-bin/hello.hoge";
    expected_cgi_mode = true;
    is_cgi_extension = false;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(is_cgi_extension, Config::is_cgi_extension(server_config, location_path));
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));

    location_path = "/cgi-bin/hello.";
    expected_cgi_mode = true;
    is_cgi_extension = false;
    expected_cgi_extension = {"py", "php"};
    expected_cgi_timeout = 60;
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_mode, Config::is_cgi_mode_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_cgi_extension, Config::get_cgi_extension, __LINE__);
    EXPECT_EQ(is_cgi_extension, Config::is_cgi_extension(server_config, location_path));
    EXPECT_EQ(expected_cgi_timeout, Config::get_cgi_timeout(server_config, location_path));



    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_err());


    location_path = "/nothing";  // same as /
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    ASSERT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    ASSERT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());


    // -------------------------------------------------------------------------

    server_name = "server1";
    address = "*";
    port = "8080";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.ok_value();


    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());





    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_err());



    // -------------------------------------------------------------------------


    server_name = "server_nothing";  // same as default_server; webserv and server1
    address = "*";
    port = "8080";

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.ok_value();


    location_path = "/";
    expected_error = false;

    expected_root = "html";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/old.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = true;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/upload";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = true;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/post";
    expected_error = false;

    expected_root = "/upload";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = 20 * ConfigInitValue::MB;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, false}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());



    location_path = "/50x.html";
    expected_error = false;

    expected_root = "www";
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.ok_value());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.ok_value());





    location_path = "nothing";
    expected_error = true;  // error

    expected_root = ConfigInitValue::kDefaultRoot;
    expected_index = ConfigInitValue::kDefaultIndex;
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = ConfigInitValue::kDefaultRedirectOn;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;


    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

    expected_method = {{kGET, true}, {kPOST, true}, {kDELETE, true}};
    expect_eq_method(server_config, location_path, expected_error, expected_method, __LINE__);

    expected_redirect = {};
    expected_redirect.return_on = true;
    expected_redirect.code = MovedPermanently;
    expected_redirect.text = "/new.html";
    expect_eq_redirect(server_config, location_path, expected_error, expected_redirect, __LINE__);

    error_page_result = Config::get_error_page(server_config, location_path, BadRequest);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, NotFound);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Config::get_error_page(server_config, location_path, InternalServerError);
    EXPECT_TRUE(error_page_result.is_err());



    // -------------------------------------------------------------------------

    server_name = "server_nothing";
    address = "*";
    port = "81";  // ng

    server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_err());  // error

}


TEST(TestConfig, ConfigGetterOK2) {
    Result<int, std::string> result;
    Config config("test/test_conf/ok/conf_ok1.conf");

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

    result = config.result();

    // print_error_msg(result, __LINE__);
    ASSERT_TRUE(result.is_ok());


    server_name = "a";
    address = "*";
    port = "81";

    ServerInfo server_info = ServerInfo(server_name, address, port);
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_a";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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
    server_config = server_config_result.ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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
    server_config = server_config_result.ok_value();

    location_path = "a";
    expected_error = false;

    expected_root = "root_c";
    expected_index = "index.html";
    expected_autoindex = ConfigInitValue::kDefaultAutoindex;
    expected_is_redirect = false;
    expected_max_body_size = ConfigInitValue::kDefaultBodySize;



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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



    expect_eq_getter(server_config, location_path, expected_error, expected_root, Config::get_root, __LINE__);
    // expect_eq_getter(server_config, location_path, expected_error, expected_index, Config::get_index, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_autoindex, Config::is_autoindex_on, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_is_redirect, Config::is_redirect, __LINE__);
    expect_eq_getter(server_config, location_path, expected_error, expected_max_body_size, Config::get_max_body_size, __LINE__);

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


TEST(TestConfig, GetServerConfig) {
    Config config("test/test_conf/ok/conf_ok1.conf");
    Result<ServerConfig, int> server_a_result, server_b_result, server_c_result;
    Result<ServerConfig, std::string> actual_result;
    ServerConfig expected_a, expected_b, expected_c;
    ServerConfig actual;

    ServerInfo server_info;
    AddressPortPair config_address_port_pair;
    HostPortPair request_host_port_pair;

    server_info.server_name = "a";
    server_info.address = "*";
    server_info.port = "81";
    server_a_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_a_result.is_ok());
    expected_a = server_a_result.ok_value();

    server_info.server_name = "b";
    server_info.address = "*";
    server_info.port = "80";
    server_b_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_b_result.is_ok());
    expected_b = server_b_result.ok_value();

    server_info.server_name = "c";
    server_info.address = "*";
    server_info.port = "81";
    server_c_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_c_result.is_ok());
    expected_c = server_c_result.ok_value();


    // server_a
    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";

    request_host_port_pair.first = "a";
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_a, actual, __LINE__);


    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "127.0.0.2";  // default
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_c, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "a";
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_a, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "192.0.0.2";  // default
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_c,  actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "b";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);


    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "b";         // ng -> default
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_c, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "c";
    request_host_port_pair.second = "81";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_c, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);


    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "b";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "*";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "127.0.0.0.0";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_ok());
    actual = actual_result.ok_value();
    expect_eq_server_config(expected_b, actual, __LINE__);

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "aa";
    request_host_port_pair.second = "80";    // ng
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());

    config_address_port_pair.first = "*";
    config_address_port_pair.second = "81";
    request_host_port_pair.first = "";      // ng
    request_host_port_pair.second = "*";    // ng
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "127.0.0.1";  // ng
    config_address_port_pair.second = "82";        // ng
    request_host_port_pair.first = "127.0.0.2";     // ng
    request_host_port_pair.second = "81";           // ng
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    // -------------------------------------------------------------------------

    config_address_port_pair.first = "";
    config_address_port_pair.second = "";
    request_host_port_pair.first = "";
    request_host_port_pair.second = "";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "a";
    config_address_port_pair.second = "1212";
    request_host_port_pair.first = "-2";
    request_host_port_pair.second = "0";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "1270.0.0.0";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "*";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "127.0.0.1";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "**";
    request_host_port_pair.second = "*";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());

    config_address_port_pair.first = "1270.0.0.0";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "*";
    request_host_port_pair.second = "121212121212121212";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "1270.0.0.0";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "*";
    request_host_port_pair.second = "a";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());


    config_address_port_pair.first = "1270.0.0.0";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "a";
    request_host_port_pair.second = "a";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());

    config_address_port_pair.first = "127.0.0.0";
    config_address_port_pair.second = "80";
    request_host_port_pair.first = "127.0.1.0";
    request_host_port_pair.second = "80";
    actual_result = config.get_server_config(config_address_port_pair, request_host_port_pair);
    ASSERT_TRUE(actual_result.is_err());
}
