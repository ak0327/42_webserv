#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "gtest/gtest.h"

#include "../../srcs/Config/Config.hpp"
#include "../../srcs/Config/IsConfigFormat/IsConfigFormat.hpp"
#include "../../srcs/HandlingString/HandlingString.hpp"
#include <algorithm>

void	compare_vector_report(int line, std::vector<std::string> target_vector, std::vector<std::string> anser_vector)
{
	std::vector<std::string>::iterator	target_vector_itr = target_vector.begin();

	while (target_vector_itr != target_vector.end())
	{
		std::cerr << *target_vector_itr << "|";
		if (std::find(anser_vector.begin(), anser_vector.end(), *target_vector_itr) == anser_vector.end())
			ADD_FAILURE_AT(__FILE__, line);
		target_vector_itr++;
	}
}

TEST(ConfigReadingTest, config_test_1) 
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

// EXPECT_EQ(false, astalisk_cgi_path.get_autoindex());
// EXPECT_EQ(false, astalisk_cgi_path.get_chunked_transferencoding_allow());
// EXPECT_EQ(1, astalisk_cgi_path.get_server_tokens());
// EXPECT_EQ(8000, astalisk_cgi_path.get_client_body_buffer_size());
// EXPECT_EQ(60, astalisk_cgi_path.get_client_body_timeout());
// EXPECT_EQ(1024, astalisk_cgi_path.get_client_header_buffer_size());
// EXPECT_EQ(60, astalisk_cgi_path.get_client_header_timeout());
// EXPECT_EQ(1024, astalisk_cgi_path.get_client_max_body_size());
// EXPECT_EQ(0, astalisk_cgi_path.get_keepaliverequests());
// EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_timeout());
// EXPECT_EQ("", astalisk_cgi_path.get_alias());
// EXPECT_EQ("", astalisk_cgi_path.get_accesslog());
// EXPECT_EQ("", astalisk_cgi_path.get_cgi_path());
// EXPECT_EQ("application/octet-stream", astalisk_cgi_path.get_default_type());
// EXPECT_EQ("", astalisk_cgi_path.get_errorlog());
// EXPECT_EQ("", astalisk_cgi_path.get_root());
// compare_vector_report(66, allconfig.get_allowmethods(), anser_allowmethods);
// compare_vector_report(83, astalisk_cgi_path.get_indexpages(), anser_indexpage_sets);

TEST(ConfigReadingTest, config_test_2) 
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

TEST(ConfigReadingTest, config_test_3) 
{
	Config	test_config("config/testconfig3.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(true, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_1) 
{
	Config	test_config("error_config/errortestconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_2) 
{
	Config	test_config("error_config/errortestconfig2.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_3) 
{
	Config	test_config("error_config/errortestconfig3.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_5) 
{
	Config	test_config("error_config/errortestconfig5.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_6) 
{
	Config	test_config("error_config/errortestconfig6.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_7) 
{
	Config	test_config("error_config/errortestconfig7.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_8) 
{
	Config	test_config("error_config/errortestconfig8.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
}

TEST(ConfigReadingTest, error_config_test_and_get_no_exist_key_1)
{
	Config	test_config("error_config/errortestconfig1.conf");
	ServerConfig	allconfig;

	EXPECT_EQ(false, test_config.get_is_config_format());
	test_config.get_same_allconfig("webserv2");
}
