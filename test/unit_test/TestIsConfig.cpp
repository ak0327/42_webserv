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
		if (std::find(anser_vector.begin(), anser_vector.end(), *target_vector_itr) == anser_vector.end())
			ADD_FAILURE_AT(__FILE__, line);
		target_vector_itr++;
	}
}

TEST(ConfigTest, config_test_1) 
{
	Config 													test_config("config/testconfig1.conf");
	std::map<std::vector<std::string>, AllConfig>			test_config_infs = test_config.get_all_configs();
	std::map<std::vector<std::string>, AllConfig>::iterator	it = test_config_infs.begin();
	// Config test_config2("config/testconfig2.conf");

	EXPECT_EQ(true, test_config.get_is_config_format());
	std::vector<std::string>			server_name;
	std::vector<std::string>			anser_server_name;
	std::vector<std::string>::iterator	server_name_itr;

	anser_server_name.push_back("__webserv1");
	server_name = it->first;
	server_name_itr = server_name.begin();
	while (server_name_itr != server_name.end())
	{
		std::cout << "server name is " << *server_name_itr << std::endl;
		if (std::find(anser_server_name.begin(), anser_server_name.end(), *server_name_itr) == anser_server_name.end())
			ADD_FAILURE_AT(__FILE__, __LINE__);
		server_name_itr++;
	}
	EXPECT_EQ(false, it->second.get_host_config().get_autoindex());
	EXPECT_EQ(false, it->second.get_host_config().get_chunked_transferencoding_allow());
	EXPECT_EQ(1, it->second.get_host_config().get_server_tokens());
	EXPECT_EQ(8000, it->second.get_host_config().get_client_body_buffer_size());
	EXPECT_EQ(60, it->second.get_host_config().get_client_body_timeout());
	EXPECT_EQ(1024, it->second.get_host_config().get_client_header_buffer_size());
	EXPECT_EQ(60, it->second.get_host_config().get_client_header_timeout());
	EXPECT_EQ(1048576, it->second.get_host_config().get_client_maxbody_size());
	EXPECT_EQ(0, it->second.get_host_config().get_keepaliverequests());
	EXPECT_EQ(0, it->second.get_host_config().get_keepalive_timeout());
	EXPECT_EQ(1024, it->second.get_host_config().get_maxBodySize());
	EXPECT_EQ("", it->second.get_host_config().get_accesslog());
	EXPECT_EQ("application/octet-stream", it->second.get_host_config().get_default_type());
	EXPECT_EQ("", it->second.get_host_config().get_errorlog());
	EXPECT_EQ("4242", it->second.get_host_config().get_port());
	EXPECT_EQ("", it->second.get_host_config().get_root());
	std::vector<std::string>	anser_allowmethod_sets;
	compare_vector_report(66, it->second.get_host_config().get_allowmethod_set(), anser_allowmethod_sets);
	std::vector<std::string>	anser_indexpage_sets;
	anser_indexpage_sets.push_back("index.html");
	anser_indexpage_sets.push_back("index.php");
	compare_vector_report(70, it->second.get_host_config().get_allowmethod_set(), anser_indexpage_sets);
	std::vector<std::string>	anser_serverpage_sets;
	anser_serverpage_sets.push_back("__webserv1");
	compare_vector_report(70, it->second.get_host_config().get_server_name(), anser_serverpage_sets);
	// EXPECT_EQ(true, test_config2.get_is_config_format());

	LocationConfig	astalisk_cgi_path = it->second.get_location_host_config("*.cgi");
	EXPECT_EQ(false, astalisk_cgi_path.get_autoindex());
	EXPECT_EQ(false, astalisk_cgi_path.get_chunked_transferencoding_allow());
	EXPECT_EQ(1, astalisk_cgi_path.get_server_tokens());
	EXPECT_EQ(8000, astalisk_cgi_path.get_client_body_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_body_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_client_header_buffer_size());
	EXPECT_EQ(60, astalisk_cgi_path.get_client_header_timeout());
	EXPECT_EQ(1048576, astalisk_cgi_path.get_client_max_body_size());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepaliverequests());
	EXPECT_EQ(0, astalisk_cgi_path.get_keepalive_timeout());
	EXPECT_EQ(1024, astalisk_cgi_path.get_maxBodySize());
	EXPECT_EQ("", astalisk_cgi_path.get_accesslog());
	EXPECT_EQ("application/octet-stream", astalisk_cgi_path.get_default_type());
	EXPECT_EQ("", astalisk_cgi_path.get_errorlog());
	EXPECT_EQ("", astalisk_cgi_path.get_root());
}