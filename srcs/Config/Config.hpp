#ifndef SRCS_CONFIG_CONFIG_HPP_
#define SRCS_CONFIG_CONFIG_HPP_

#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include "HandlingString/ConfigHandlingString.hpp"
#include "LocationConfig/LocationConfig.hpp"
#include "ServerConfig/ServerConfig.hpp"
#include "ErrorPage/ErrorPage.hpp"
class	LocationConfig;
class	ServerConfig;

class	Config
{
 private:
		std::map<std::string, ServerConfig>							server_configs;

 public:
		explicit Config(std::string	const &config);
		~Config();
		void	config_linecheck(const std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos);
		void	handle_serverinfs(const std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos);
		bool	handle_locationinfs(std::string &line, bool &in_location, LocationConfig &location_config, std::map<std::string, ServerConfig>::iterator &it, std::string &location_path);
		std::map<std::string, ServerConfig>		get_server_config(){ return (this->server_configs); }
		void	config_location_check(std::string &line, bool &in_server, bool &in_location, LocationConfig &location_config, std::string &location_path, \
		std::map<std::string, ServerConfig>::iterator	&it, size_t &pos);
		std::string	get_location_path(const std::string &locationfield_word);
		void	show_configinfos();
		class	ConfigError
		{
			public:  // NOLINT
				virtual const char* what() const throw(){ return "This is Config Error"; }
		};
};

#endif  // SRCS_CONFIG_CONFIG_HPP_
