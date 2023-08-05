#ifndef Config_HPP
#define Config_HPP

#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#include "HandlingString.hpp"
#include "LocationConfig.hpp"
#include "ServerConfig.hpp"

class	LocationConfig;
class	ServerConfig;
//config
//     str1 serverconfig
//                locationconfig
//     str2 serverconfig2

class	Config
{
	private:
		std::map<std::string, ServerConfig>							server_configs;

	public:
		Config(std::string	const &config);
		~Config();

		void									config_linecheck(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos);
		void									handle_serverinfs(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos);
		bool									handle_locationinfs(std::string &line,bool &in_location, LocationConfig &location_config, std::map<std::string, ServerConfig>::iterator	&it, std::string &location_path);
		
		std::map<std::string, ServerConfig>		get_server_config(){ return (this->server_configs); };

		// void									reset_contents();
		void									config_location_check(std::string &line, bool &in_server, bool &in_location, LocationConfig &location_config, std::string &location_path, std::map<std::string, ServerConfig>::iterator	&it, size_t &pos);
		void									show_configinfos();


		class	ConfigError
		{
			public:
				virtual const char* what() const throw(){ return "This is Config Error"; };
		};
};

#endif