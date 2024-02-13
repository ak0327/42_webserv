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


TEST(TestConf, ConfigurationGetterOK1) {
    Result<int, std::string> result;
    Configuration config("test/test_conf/ok/parse_ok1.conf");

    std::string location_path, root, index, error_page;
    bool autoindex, is_redirect;
    std::size_t max_body_size;
    ReturnDirective redirect;
    Result<std::string, int> error_page_result;
    Result<ReturnDirective, int> redirect_result;
    ServerConfig server_config;
    Result<ServerConfig, int> server_config_result;

    result = config.get_result();

    // print_error_msg(result, __LINE__);
    ASSERT_TRUE(result.is_ok());

    ServerInfo server_info = ServerInfo("webserv", "*", "8080");
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "/";

    root = "html";
    index = "index.html";
    autoindex = false;
    is_redirect = false;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/old.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_TRUE(config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "/upload";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = true;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";

    root = "/upload";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = 20 * ConfigInitValue::MB;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_FALSE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "=/50x.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "nothing->same_as_default_server";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());

    // -------------------------------------------------------------------------

    server_info = ServerInfo("server1", "*", "8080");
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "/";

    root = "html";
    index = "index.html";
    autoindex = false;
    is_redirect = false;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/old.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_TRUE(config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "/upload";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = true;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";

    root = "/upload";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = 20 * ConfigInitValue::MB;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_FALSE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "=/50x.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "nothing->same_as_default_server";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());

    // -------------------------------------------------------------------------

    server_info = ServerInfo("nothing->same_as_default_server", "*", "8080");
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_ok());
    server_config = server_config_result.get_ok_value();

    location_path = "/";

    root = "html";
    index = "index.html";
    autoindex = false;
    is_redirect = false;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/old.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_TRUE(config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "/upload";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = true;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "/post";

    root = "/upload";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = 20 * ConfigInitValue::MB;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_FALSE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());


    location_path = "=/50x.html";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());



    location_path = "nothing->same_as_default_server";

    root = "www";
    index = ConfigInitValue::kDefaultIndex;
    autoindex = ConfigInitValue::kDefaultAutoindex;
    is_redirect = ConfigInitValue::kDefaultRedirectOn;
    max_body_size = ConfigInitValue::kDefaultBodySize;

    EXPECT_EQ(root, Configuration::get_root(server_config, location_path));
    EXPECT_EQ(index, Configuration::get_index(server_config, location_path));

    EXPECT_EQ(autoindex, config.is_autoindex_on(server_config, location_path));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kGET));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kPOST));
    EXPECT_TRUE(config.is_method_allowed(server_config, location_path, kDELETE));
    EXPECT_EQ(is_redirect, config.is_redirect(server_config, location_path));

    EXPECT_EQ(max_body_size, config.get_max_body_size(server_config, location_path));

    error_page_result = Configuration::get_error_page(server_config, location_path, 400);
    EXPECT_TRUE(error_page_result.is_err());
    error_page_result = Configuration::get_error_page(server_config, location_path, 404);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/404.html", error_page_result.get_ok_value());
    error_page_result = Configuration::get_error_page(server_config, location_path, 500);
    EXPECT_TRUE(error_page_result.is_ok());
    EXPECT_EQ("/50x.html", error_page_result.get_ok_value());

    // -------------------------------------------------------------------------

    server_info = ServerInfo("nothing", "*", "81");
    server_config_result = config.get_server_config(server_info);
    ASSERT_TRUE(server_config_result.is_err());

}
