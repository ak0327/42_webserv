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
class	LocationConfig;
class	ServerConfig;

class	Config
{
 private:
		std::map<std::string, ServerConfig>							server_configs;

 public:
		explicit Config(std::string	const &config);
		~Config();
		void	config_linecheck(const std::string &line, const bool &in_server, const bool &in_location, const ServerConfig &server_config, size_t pos);
		void	handle_serverinfs(const std::string &line, const bool &in_server, const bool &in_location, const ServerConfig &server_config, size_t pos);
		bool	handle_locationinfs(const std::string &line, const bool &in_location, const LocationConfig &location_config, std::map<std::string, \
		ServerConfig>::iterator &it, const std::string &location_path);
		std::map<std::string, ServerConfig>		get_server_config(){ return (this->server_configs); }
		void	config_location_check(const std::string &line, const bool &in_server, const bool &in_location, const LocationConfig &location_config, \
		const std::string &location_path, std::map<std::string, ServerConfig>::iterator	&it, size_t &pos);
		void	show_configinfos();
		class	ConfigError
		{
			public:  // NOLINT
				virtual const char* what() const throw(){ return "This is Config Error"; }
		};
};

#endif  // SRCS_CONFIG_CONFIG_HPP_
