#include <algorithm>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Config.hpp"
#include "IsConfigFormat.hpp"
#include "HandlingString.hpp"

void	compare_vector_report(int line, std::vector<std::string> target_vector, std::vector<std::string> anser_vector)
{
	std::vector<std::string>::iterator	target_vector_itr = target_vector.begin();

	while (target_vector_itr != target_vector.end())
	{
		// std::cerr << *target_vector_itr << "|";
		if (std::find(anser_vector.begin(), anser_vector.end(), *target_vector_itr) == anser_vector.end())
			ADD_FAILURE_AT(__FILE__, line);
		target_vector_itr++;
	}
}

TEST(ConfigReadingTest, ConfigTest1)
{
	Config	test_config("config/testconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
	allconfig = test_config.get_same_allconfig("aaa").get_server_config();
	LocationConfig	astalisk_cgi_path = test_config.get_same_allconfig("aaa").get_location_config("*.cgi");

	// configに記載があるもの server block //
	EXPECT_EQ("4242", allconfig.get_port());
	std::vector<std::string>	anser_indexpage_sets;
	anser_indexpage_sets.push_back("index.html");
	anser_indexpage_sets.push_back("index.php");
	compare_vector_report(__LINE__, allconfig.get_index(), anser_indexpage_sets);
	// -------------------------------- //

	// configに記載があるもの location block //
	std::vector<std::string>	anser_allowmethods;
	anser_allowmethods.push_back("POST");
	compare_vector_report(__LINE__, astalisk_cgi_path.get_index(), anser_allowmethods);
	EXPECT_EQ("test/index.php", astalisk_cgi_path.get_cgi_path());
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
	anser_allowmethods.clear();
	compare_vector_report(__LINE__, allconfig.get_allow_methods(), anser_allowmethods);
	// -------------------------------- //

	// configに記載がないもの location block //
	EXPECT_EQ(false, astalisk_cgi_path.get_autoindex());
	EXPECT_EQ(false, astalisk_cgi_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, astalisk_cgi_path.get_server_tokens());
	EXPECT_EQ(8000, astalisk_cgi_path.get_client_body_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_body_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_client_header_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_header_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_client_max_body_size());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_requests());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_timeout());
	EXPECT_EQ("", astalisk_cgi_path.get_alias());
	EXPECT_EQ("", astalisk_cgi_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", astalisk_cgi_path.get_default_type());
	EXPECT_EQ("", astalisk_cgi_path.get_errorlog());
	EXPECT_EQ("", astalisk_cgi_path.get_root());
	compare_vector_report(__LINE__, astalisk_cgi_path.get_index(), anser_indexpage_sets);
	// -------------------------------- //
}

// EXPECT_EQ(false, allconfig.get_autoindex());
// EXPECT_EQ(false, allconfig.get_chunked_transferencoding_allow());
// EXPECT_EQ(1, allconfig.get_server_tokens());
// EXPECT_EQ(8000, allconfig.get_client_body_buffer_size());
// EXPECT_EQ(60, allconfig.get_client_body_timeout());
// EXPECT_EQ(1024, allconfig.get_client_header_buffer_size());
// EXPECT_EQ(60, allconfig.get_client_header_timeout());
// EXPECT_EQ(0, allconfig.get_keepalive_requests());
// EXPECT_EQ(0, allconfig.get_keepalive_timeout());
// EXPECT_EQ(1024, allconfig.get_client_max_body_size());
// EXPECT_EQ("", allconfig.get_accesslog());
// EXPECT_EQ("application/octet-stream", allconfig.get_default_type());
// EXPECT_EQ("", allconfig.get_errorlog());
// EXPECT_EQ("", allconfig.get_port());
// EXPECT_EQ("", allconfig.get_root());
// compare_vector_report(66, allconfig.get_allowmethods(), anser_allowmethods);
// compare_vector_report(66, allconfig.get_indexpages(), anser_indexpages);

// EXPECT_EQ(false, 								*.get_autoindex());
// EXPECT_EQ(false, 								*.get_chunked_transferencoding_allow());
// EXPECT_EQ(1,										*.get_server_tokens());
// EXPECT_EQ(8000,									*.get_client_body_buffer_size());
// EXPECT_EQ(60,									*.get_client_body_timeout());
// EXPECT_EQ(1024,									*.get_client_header_buffer_size());
// EXPECT_EQ(60,									*.get_client_header_timeout());
// EXPECT_EQ(1024,									*.get_client_max_body_size());
// EXPECT_EQ(0,										*.get_keepaliverequests());
// EXPECT_EQ(0,										*.get_keepalive_timeout());
// EXPECT_EQ("",									*.get_alias());
// EXPECT_EQ("",									*.get_accesslog());
// EXPECT_EQ("",									*.get_cgi_path());
// EXPECT_EQ("application/octet-stream",			*.get_default_type());
// EXPECT_EQ("", 									*.get_errorlog());
// EXPECT_EQ("", 									*.get_root());
// compare_vector_report(83, anser_indexpage_sets,	*.get_indexpages());

TEST(ConfigReadingTest, ConfigTest2)
{
	Config	test_config("config/testconfig2.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
	allconfig = test_config.get_same_allconfig("webserv1").get_server_config();
	LocationConfig	astalisk_cgi_path = test_config.get_same_allconfig("webserv1").get_location_config("*.cgi");
	LocationConfig	root_path = test_config.get_same_allconfig("webserv1").get_location_config("/");
	LocationConfig	autoindex_path = test_config.get_same_allconfig("webserv1").get_location_config("/autoindex/");
	LocationConfig	autoindex_path2 = test_config.get_same_allconfig("webserv1").get_location_config("/autoindex2/");

	// configに記載があるもの server block //
	EXPECT_EQ("4242", allconfig.get_port());
	std::vector<std::string>	anser_server_name;
	anser_server_name.push_back("aa");
	anser_server_name.push_back("webserv1");
	anser_server_name.push_back("webserve_extention");
	compare_vector_report(__LINE__, allconfig.get_server_name(), anser_server_name);
	std::vector<std::string>	anser_indexpage_sets;
	anser_indexpage_sets.push_back("index.html");
	anser_indexpage_sets.push_back("index.php");
	compare_vector_report(__LINE__, allconfig.get_index(), anser_indexpage_sets);
	// -------------------------------- //

	// configに記載があるもの location block //
	std::vector<std::string>	anser_allowmethods;
	anser_allowmethods.push_back("POST");
	compare_vector_report(__LINE__, astalisk_cgi_path.get_index(), anser_allowmethods);
	EXPECT_EQ("test/index.php", astalisk_cgi_path.get_cgi_path());

	EXPECT_EQ("./docs/", root_path.get_alias());

	EXPECT_EQ("./docs/autoindex/", autoindex_path.get_alias());
	EXPECT_EQ(true, autoindex_path.get_autoindex());

	EXPECT_EQ("./docs/autoindex2/", autoindex_path2.get_alias());
	EXPECT_EQ(true, autoindex_path2.get_autoindex());
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
	anser_allowmethods.clear();
	compare_vector_report(__LINE__, allconfig.get_allow_methods(), anser_allowmethods);
	// -------------------------------- //

	// configに記載がないもの location block //
	EXPECT_EQ(false, astalisk_cgi_path.get_autoindex());
	EXPECT_EQ(false, astalisk_cgi_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, astalisk_cgi_path.get_server_tokens());
	EXPECT_EQ(8000, astalisk_cgi_path.get_client_body_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_body_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_client_header_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_header_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_client_max_body_size());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_requests());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_timeout());
	EXPECT_EQ("", astalisk_cgi_path.get_alias());
	EXPECT_EQ("", astalisk_cgi_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", astalisk_cgi_path.get_default_type());
	EXPECT_EQ("", astalisk_cgi_path.get_errorlog());
	EXPECT_EQ("", astalisk_cgi_path.get_root());
	compare_vector_report(__LINE__, astalisk_cgi_path.get_index(), anser_indexpage_sets);

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
	compare_vector_report(__LINE__, root_path.get_index(), anser_indexpage_sets);
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
	allconfig = test_config.get_same_allconfig("webserv1").get_server_config();
	LocationConfig	root_path = test_config.get_same_allconfig("webserv1").get_location_config("/");

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
	EXPECT_EQ("4242", allconfig.get_port());
	EXPECT_EQ("/www/", allconfig.get_root());
	std::vector<std::string>	anser_allowmethods;
	anser_allowmethods.push_back("GET");
	anser_allowmethods.push_back("POST");
	compare_vector_report(__LINE__, allconfig.get_allow_methods(), anser_allowmethods);
	std::vector<std::string>	anser_indexpages;
	anser_indexpages.push_back("index.html");
	compare_vector_report(__LINE__, allconfig.get_index(), anser_indexpages);
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
	anser_indexpages.clear();
	anser_indexpages.push_back("index_html.html");
	compare_vector_report(__LINE__, anser_indexpages, root_path.get_index());
	// -------------------------------- //

	// configに記載がないもの server block //

	// -------------------------------- //

	// configに記載がないもの location block //

	// -------------------------------- //
}

TEST(ConfigReadingTest, ErrorConfigTest1)
{
	Config	test_config("error_config/errortestconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest2)
{
	Config	test_config("error_config/errortestconfig2.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest3)
{
	Config	test_config("error_config/errortestconfig3.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest5)
{
	Config	test_config("error_config/errortestconfig5.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest6)
{
	Config	test_config("error_config/errortestconfig6.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest7)
{
	Config	test_config("error_config/errortestconfig7.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest8)
{
	Config	test_config("error_config/errortestconfig8.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTest9)
{
	Config	test_config("error_config/errortestconfig9.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, ErrorConfigTestand_get_no_exist_key_1)
{
	Config	test_config("error_config/errortestconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
	test_config.get_same_allconfig("webserv2");
}
