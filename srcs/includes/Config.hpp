#ifndef Config_HPP
#define Config_HPP

#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#include "ServerConfig.hpp"
#include "LocationConfig.hpp"

class	ServerConfig;
class	LocationConfig;

class	Config
{
	private:
		std::map<std::string, ServerConfig>							server_config;

	public:
		Config(std::string	const &config);
		~Config();
		std::map<std::string, ServerConfig>							get_server_config(){ return (this->server_config); };

		class	ConfigError
		{
			public:
				virtual const char* what() const throw(){};
		};
};

#endif