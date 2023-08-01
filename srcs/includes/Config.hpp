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
		std::map<std::string, ServerConfig>							server_configs;

	public:
		Config(std::string	const &config);
		~Config();

		void									config_linecheck(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config);
		void									handle_serverinfs(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config);

		void									ready_serverconfig();
		void									insert_severconfig_value();
		
		std::map<std::string, ServerConfig>		get_server_config(){ return (this->server_configs); };

		void									config_linecheck(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config);

		void									handle_serverinfs(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config);
		void									ready_serverconfig();
		void									insert_severconfig_value();

		// void									reset_contents();
		void									confcheck(std::string const &conf);

		class	ConfigError
		{
			public:
				virtual const char* what() const throw(){};
		};
};

#endif