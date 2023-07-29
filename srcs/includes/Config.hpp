#ifndef Config_HPP
#define Config_HPP

#include <map>

#include "ServerConfig.hpp"
#include "LocationConfig.hpp"

class	ServerConfig;
class	LocationConfig;

class	Config
{
	private:
		ServerConfig	server_config;
		LocationConfig	location_config;

	public:
};

#endif