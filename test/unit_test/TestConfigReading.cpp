#include <algorithm>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Config.hpp"
#include "IsConfigFormat.hpp"
#include "HandlingString.hpp"

void	compare_vector_report(int line, std::vector<std::string> target_vector, std::vector<std::string> answer_vector)
{
	std::vector<std::string>::iterator	target_vector_itr = target_vector.begin();

	while (target_vector_itr != target_vector.end())
	{
		// std::cerr << *target_vector_itr << "|";
		if (std::find(answer_vector.begin(), answer_vector.end(), *target_vector_itr) == answer_vector.end())
			ADD_FAILURE_AT(__FILE__, line);
		target_vector_itr++;
	}
}

TEST(ConfigReadingTest, ConfigTest1)
{
	Config	test_config("config/testconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
	allconfig = test_config.get_allconfig("aaa").get_server_config();
	LocationConfig	asterisk_cgi_path = test_config.get_allconfig("aaa").get_location_config("*.cgi");

	// configに記載があるもの server block //
	EXPECT_EQ(4242, allconfig.get_port());
	std::vector<std::string>	answer_indexpage_sets;
	answer_indexpage_sets.push_back("index.html");
	answer_indexpage_sets.push_back("index.php");
	compare_vector_report(__LINE__, allconfig.get_index(), answer_indexpage_sets);
	// -------------------------------- //

	// configに記載があるもの location block //
	std::vector<std::string>	answer_allowmethods;
	std::vector<std::string>	answer_index;
	answer_index.push_back("index.html");
	answer_index.push_back("index.php");
	compare_vector_report(__LINE__, asterisk_cgi_path.get_index(), answer_index);
	EXPECT_EQ("test/index.php", asterisk_cgi_path.get_cgi_path());
	// -------------------------------- //

	// configに記載がないもの server block //
	EXPECT_EQ(false, allconfig.get_autoindex());
	EXPECT_EQ(false, allconfig.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, allconfig.get_server_tokens());
	EXPECT_EQ(8000, allconfig.get_client_body_buffer_size());
	EXPECT_EQ(60, allconfig.get_client_body_timeout());
	EXPECT_EQ(1024, allconfig.get_client_header_buffer_size());
	EXPECT_EQ(60, allconfig.get_client_header_timeout());
	EXPECT_EQ(0, allconfig.get_keepalive_requests());
	EXPECT_EQ(0, allconfig.get_keepalive_timeout());
	EXPECT_EQ(1024, allconfig.get_client_max_body_size());
	EXPECT_EQ("", allconfig.get_accesslog());
	EXPECT_EQ("application/octet-stream", allconfig.get_default_type());
	EXPECT_EQ("", allconfig.get_errorlog());
	EXPECT_EQ("", allconfig.get_root());
	answer_allowmethods.clear();
	compare_vector_report(__LINE__, allconfig.get_allow_methods(), answer_allowmethods);
	// -------------------------------- //

	// configに記載がないもの location block //
	EXPECT_EQ(false, asterisk_cgi_path.get_autoindex());
	EXPECT_EQ(false, asterisk_cgi_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, asterisk_cgi_path.get_server_tokens());
	EXPECT_EQ(8000, asterisk_cgi_path.get_client_body_buffer_size());
	EXPECT_EQ(60, asterisk_cgi_path.get_client_body_timeout());
	EXPECT_EQ(1024, asterisk_cgi_path.get_client_header_buffer_size());
	EXPECT_EQ(60, asterisk_cgi_path.get_client_header_timeout());
	EXPECT_EQ(1024, asterisk_cgi_path.get_client_max_body_size());
	EXPECT_EQ(0, asterisk_cgi_path.get_keepalive_requests());
	EXPECT_EQ(0, asterisk_cgi_path.get_keepalive_timeout());
	EXPECT_EQ("", asterisk_cgi_path.get_alias());
	EXPECT_EQ("", asterisk_cgi_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", asterisk_cgi_path.get_default_type());
	EXPECT_EQ("", asterisk_cgi_path.get_errorlog());
	EXPECT_EQ("", asterisk_cgi_path.get_root());
	compare_vector_report(__LINE__, asterisk_cgi_path.get_index(), answer_indexpage_sets);
	// -------------------------------- //
}

TEST(ConfigReadingTest, ConfigTest2)
{
	Config	test_config("config/testconfig2.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
	allconfig = test_config.get_allconfig("webserv1").get_server_config();
	AllConfig webserv_config = test_config.get_allconfig("webserv1");


	std::vector<std::string> answer_server_name;
	std::vector<std::string> answer_index;
	std::vector<std::string> answer_allowmethods;
	std::vector<std::string> answer_error_pages;


	EXPECT_EQ(false, allconfig.get_autoindex());
	EXPECT_EQ(false, allconfig.get_chunked_transferencoding_allow());

	EXPECT_EQ(1, allconfig.get_server_tokens());
	EXPECT_EQ(8000, allconfig.get_client_body_buffer_size());
	EXPECT_EQ(60, allconfig.get_client_body_timeout());
	EXPECT_EQ(1024, allconfig.get_client_header_buffer_size());
	EXPECT_EQ(60, allconfig.get_client_header_timeout());
	EXPECT_EQ(1024, allconfig.get_client_max_body_size());
	EXPECT_EQ(0, allconfig.get_keepalive_requests());
	EXPECT_EQ(0, allconfig.get_keepalive_timeout());

	EXPECT_EQ("", allconfig.get_accesslog());
	EXPECT_EQ(".cgi", allconfig.get_cgi_extension());
	EXPECT_EQ("application/octet-stream", allconfig.get_default_type());
	EXPECT_EQ("", allconfig.get_errorlog());
	EXPECT_EQ(4242, allconfig.get_port());
	EXPECT_EQ("", allconfig.get_root());

	answer_server_name = {"webserv1", "webserve_extention", "aa"};
	answer_allowmethods = {};
	answer_index = {"index.html", "index.php"};
	EXPECT_EQ(answer_server_name, allconfig.get_server_name());
	EXPECT_EQ(answer_allowmethods, allconfig.get_allow_methods());
	EXPECT_EQ(answer_index, allconfig.get_index());

	// -------------------------------- //

	//    location *.cgi {
	// 		allow_methods POST;
	// 		cgi_path test/index.php;
	// 	}
	LocationConfig asterisk_cgi_path = webserv_config.get_location_config("*.cgi");

	answer_server_name = {"webserv1", "webserve_extention", "aa"};
	answer_allowmethods = {"POST"};
	answer_index = {"index.html", "index.php"};
	EXPECT_EQ(answer_server_name, allconfig.get_server_name());
	EXPECT_EQ(answer_allowmethods, asterisk_cgi_path.get_allow_methods());
	EXPECT_EQ(answer_index, asterisk_cgi_path.get_index());

	EXPECT_EQ("test/index.php", asterisk_cgi_path.get_cgi_path());

	EXPECT_EQ(false, asterisk_cgi_path.get_autoindex());
	EXPECT_EQ(false, asterisk_cgi_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, asterisk_cgi_path.get_server_tokens());
	EXPECT_EQ(8000, asterisk_cgi_path.get_client_body_buffer_size());
	EXPECT_EQ(60, asterisk_cgi_path.get_client_body_timeout());
	EXPECT_EQ(1024, asterisk_cgi_path.get_client_header_buffer_size());
	EXPECT_EQ(60, asterisk_cgi_path.get_client_header_timeout());
	EXPECT_EQ(1024, asterisk_cgi_path.get_client_max_body_size());
	EXPECT_EQ(0, asterisk_cgi_path.get_keepalive_requests());
	EXPECT_EQ(0, asterisk_cgi_path.get_keepalive_timeout());
	EXPECT_EQ("", asterisk_cgi_path.get_alias());
	EXPECT_EQ("", asterisk_cgi_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", asterisk_cgi_path.get_default_type());
	EXPECT_EQ("", asterisk_cgi_path.get_errorlog());
	EXPECT_EQ("", asterisk_cgi_path.get_root());
	// compare_vector_report(__LINE__, asterisk_cgi_path.get_index(), answer_index);



	//    location / {
	//         alias ./docs/;
	//     }
	LocationConfig root_path = webserv_config.get_location_config("/");
	EXPECT_EQ("./docs/", root_path.get_alias());

	answer_server_name = {"webserv1", "webserve_extention", "aa"};
	answer_allowmethods = {};
	answer_index = {"index.html", "index.php"};
	EXPECT_EQ(answer_server_name, root_path.get_server_name());
	EXPECT_EQ(answer_allowmethods, root_path.get_allow_methods());
	EXPECT_EQ(answer_index, root_path.get_index());

	EXPECT_EQ(false, root_path.get_autoindex());
	EXPECT_EQ(false, root_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, root_path.get_server_tokens());
	EXPECT_EQ(8000, root_path.get_client_body_buffer_size());
	EXPECT_EQ(60, root_path.get_client_body_timeout());
	EXPECT_EQ(1024, root_path.get_client_header_buffer_size());
	EXPECT_EQ(60, root_path.get_client_header_timeout());
	EXPECT_EQ(1024, root_path.get_client_max_body_size());
	EXPECT_EQ(0, root_path.get_keepalive_requests());
	EXPECT_EQ(0, root_path.get_keepalive_timeout());
	EXPECT_EQ("", root_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", root_path.get_default_type());
	EXPECT_EQ("", root_path.get_errorlog());
	EXPECT_EQ("", root_path.get_root());



	//     location /autoindex/ {
	//         alias ./docs/autoindex/;
	//         autoindex on;
	//     }
	LocationConfig autoindex_path = webserv_config.get_location_config("/autoindex/");
	EXPECT_EQ("./docs/autoindex/", autoindex_path.get_alias());
	EXPECT_EQ(true, autoindex_path.get_autoindex());


	//     location /autoindex2/ {
	//         alias ./docs/autoindex2/;
	//         autoindex on;
	//     }
	LocationConfig autoindex_path2 = webserv_config.get_location_config("/autoindex2/");
	EXPECT_EQ("./docs/autoindex2/", autoindex_path2.get_alias());
	EXPECT_EQ(true, autoindex_path2.get_autoindex());


	//     location /autoindex3/ {
	//         alias ./docs/autoindex3/;
	//         autoindex off;
	//     }
	LocationConfig autoindex_path3 = webserv_config.get_location_config("/autoindex3/");
	EXPECT_EQ("./docs/autoindex3/", autoindex_path3.get_alias());
	EXPECT_EQ(false, autoindex_path3.get_autoindex());


	//     location /dir/ {
	//         allow_methods DELETE;
	//         alias ./docs/dir/;
	//         index hello.html;
	//     }
	LocationConfig dir = webserv_config.get_location_config("/dir/");
	answer_allowmethods = {"DELETE"};
	answer_index = {"hello.html"};

	EXPECT_EQ(answer_allowmethods, dir.get_allow_methods());
	EXPECT_EQ("./docs/dir/", dir.get_alias());
	EXPECT_EQ(answer_index, dir.get_index());


	//     location /error_page/ {
	//         alias ./docs/error_page/;
	//         # error_page 404 docs/error_page/404.html;
	//     }
	LocationConfig error_page = webserv_config.get_location_config("/error_page/");
	answer_error_pages = {"404", "docs/error_page/404.html"};
	// todo: map[404] = "docs/error_page/404.html";
	EXPECT_EQ(answer_error_pages, error_page.get_errorpages());


	//     location /upload/ {
	//         allow_methods POST;
	//         alias ./docs/upload/;
	//         upload_path ./docs/upload/;
	//         client_max_body_size 20000;
	//     }
	LocationConfig upload = webserv_config.get_location_config("/upload/");
	answer_allowmethods = {"POST"};
	EXPECT_EQ(answer_allowmethods, upload.get_allow_methods());
	EXPECT_EQ("./docs/upload/", upload.get_alias());
	EXPECT_EQ("./docs/upload/", upload.get_upload_path());
	EXPECT_EQ(20000, upload.get_client_max_body_size());


	//     location /upload2/ {
	//         allow_methods POST;
	//         alias ./docs/upload2/;
	//         upload_path ./docs/upload2/;
	//         client_max_body_size 10;
	//     }
	LocationConfig upload2 = webserv_config.get_location_config("/upload2/");
	answer_allowmethods = {"POST"};
	EXPECT_EQ(answer_allowmethods, upload2.get_allow_methods());
	EXPECT_EQ("./docs/upload2/", upload2.get_alias());
	EXPECT_EQ("./docs/upload2/", upload2.get_upload_path());
	EXPECT_EQ(10, upload2.get_client_max_body_size());

	// -------------------------------- //
}

TEST(ConfigReadingTest, ConfigTest3)
{
	Config	test_config("config/testconfig3.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ConfigTest4)
{
	Config	test_config("config/testconfig4.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
	allconfig = test_config.get_allconfig("webserv1").get_server_config();
	LocationConfig	root_path = test_config.get_allconfig(
			"webserv1").get_location_config("/");

	// configに記載があるもの server block //
	EXPECT_EQ(true, allconfig.get_autoindex());
	EXPECT_EQ(true, allconfig.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, allconfig.get_server_tokens());
	EXPECT_EQ(3000, allconfig.get_client_body_buffer_size());
	EXPECT_EQ(60, allconfig.get_client_body_timeout());
	EXPECT_EQ(3000, allconfig.get_client_header_buffer_size());
	EXPECT_EQ(30, allconfig.get_client_header_timeout());
	EXPECT_EQ(10, allconfig.get_keepalive_requests());
	EXPECT_EQ(10, allconfig.get_keepalive_timeout());
	EXPECT_EQ(3000, allconfig.get_client_max_body_size());
	EXPECT_EQ("access_log", allconfig.get_accesslog());
	EXPECT_EQ("html/plain", allconfig.get_default_type());
	EXPECT_EQ("error_log", allconfig.get_errorlog());
	EXPECT_EQ(4242, allconfig.get_port());
	EXPECT_EQ("/www/", allconfig.get_root());
	std::vector<std::string>	answer_allowmethods;
	answer_allowmethods.push_back("GET");
	answer_allowmethods.push_back("POST");
	compare_vector_report(__LINE__, allconfig.get_allow_methods(), answer_allowmethods);
	std::vector<std::string>	answer_indexpages;
	answer_indexpages.push_back("index.html");
	compare_vector_report(__LINE__, allconfig.get_index(), answer_indexpages);
	// -------------------------------- //

	// configに記載があるもの location block //
	EXPECT_EQ(false, 								root_path.get_autoindex());
	EXPECT_EQ(false, 								root_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(2,									root_path.get_server_tokens());
	EXPECT_EQ(1000,									root_path.get_client_body_buffer_size());
	EXPECT_EQ(20,									root_path.get_client_body_timeout());
	EXPECT_EQ(1000,									root_path.get_client_header_buffer_size());
	EXPECT_EQ(90,									root_path.get_client_header_timeout());
	EXPECT_EQ(10000,								root_path.get_client_max_body_size());
	EXPECT_EQ(2,									root_path.get_keepalive_requests());
	EXPECT_EQ(60,									root_path.get_keepalive_timeout());
	EXPECT_EQ("alias",								root_path.get_alias());
	EXPECT_EQ("access_log_root",					root_path.get_accesslog());
	EXPECT_EQ("honyara",							root_path.get_cgi_path());
	EXPECT_EQ("text/js",							root_path.get_default_type());
	EXPECT_EQ("error_log_root", 					root_path.get_errorlog());
	EXPECT_EQ("alias_root", 						root_path.get_root());
	answer_indexpages.clear();
	answer_indexpages.push_back("index_html.html");
	compare_vector_report(__LINE__, answer_indexpages, root_path.get_index());
	// -------------------------------- //

	// configに記載がないもの server block //

	// -------------------------------- //

	// configに記載がないもの location block //

	// -------------------------------- //
}

TEST(ConfigReadingTest, ErrorConfigTestand_get_no_exist_key_1)
{
	Config	test_config("error_config/errortestconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
	test_config.get_allconfig("webserv2");
}
