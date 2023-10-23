#include "AllConfig.hpp"

AllConfig::AllConfig(){}

AllConfig::AllConfig(const AllConfig &other)
{
	this->_server_config = other.get_server_config();
	this->_location_config_map = other._location_config_map;
}

AllConfig::AllConfig(const ServerConfig &server_config, \
						const std::map<std::string, LocationConfig> &location_config_map)
{
	this->_server_config = server_config;
	this->_location_config_map = location_config_map;
}

AllConfig& AllConfig::operator=(const AllConfig &other)
{
	if (this == &other)
		return *this;
	this->_server_config = other.get_server_config();
	this->_location_config_map = other._location_config_map;
	return *this;
}

AllConfig::~AllConfig(){}

void	AllConfig::set_server_config(const ServerConfig &server_config)
{
	this->_server_config = server_config;
}

void	AllConfig::set_location_config(const std::string &location_path, \
										const LocationConfig &location_config)
{
	this->_location_config_map[location_path] = location_config;
}

void	AllConfig::clear_information()
{
	this->_server_config.clear_serverconfig();
	this->_location_config_map.clear();
}

void	AllConfig::clear_location_information()
{
	this->_location_config_map.clear();
}

ServerConfig AllConfig::get_server_config() const
{
	return (this->_server_config);
}

LocationConfig AllConfig::get_location_config(const std::string &location_path)
{
	return (this->_location_config_map[location_path]);
}

std::map<std::string, LocationConfig> AllConfig::get_location_config_map()
{
	return (this->_location_config_map);
}
