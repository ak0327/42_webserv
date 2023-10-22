#include "AllConfig.hpp"

AllConfig::AllConfig(){}

AllConfig::AllConfig(const AllConfig &other)
{
	this->_host_config = other._host_config;
	this->_location_config_map = other._location_config_map;
}

AllConfig::AllConfig(const ServerConfig &host_config, \
						const std::map<std::string, LocationConfig> &location_config_map)
{
	this->_host_config = host_config;
	this->_location_config_map = location_config_map;
}

AllConfig& AllConfig::operator=(const AllConfig &other)
{
	if (this == &other)
		return *this;
	this->_host_config = other._host_config;
	this->_location_config_map = other._location_config_map;
	return *this;
}

AllConfig::~AllConfig(){}

void	AllConfig::set_server_config(const ServerConfig &host_config)
{
	this->_host_config = host_config;
}

void	AllConfig::set_location_config(const std::string &location_path, \
										const LocationConfig &location_config)
{
	this->_location_config_map[location_path] = location_config;
}

void	AllConfig::clear_information()
{
	this->_host_config.clear_serverconfig();
	this->_location_config_map.clear();
}

void	AllConfig::clear_location_information()
{
	this->_location_config_map.clear();
}

ServerConfig AllConfig::get_server_config()
{
	return (this->_host_config);
}

LocationConfig AllConfig::get_location_config(const std::string &location_path)
{
	return (this->_location_config_map[location_path]);
}
