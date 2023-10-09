#include "AllConfig.hpp"

AllConfig::AllConfig(){}

AllConfig::AllConfig(const ServerConfig &host_config, const std::map<std::string, LocationConfig> &_location_config)
{
	this->_host_config = host_config;
	this->_location_config = _location_config;
}

AllConfig& AllConfig::operator=(const AllConfig &other)
{
	if (this == &other)
		return *this;
	this->_host_config = other._host_config;
	this->_location_config = other._location_config;
	return *this;
}

AllConfig::~AllConfig(){}

void	AllConfig::set_host_config(const ServerConfig &host_config)
{
	this->_host_config = host_config;
}

void	AllConfig::set_location_config(const std::string &location_path, const LocationConfig &location_config)
{
	this->_location_config[location_path] = location_config;
}

void	AllConfig::clear_information()
{
	this->_host_config.clear_serverconfig();
	this->_location_config.clear();
}

void	AllConfig::clear_location_information()
{
	this->_location_config.clear();
}

ServerConfig AllConfig::get_host_config()
{
	return (this->_host_config);
}

LocationConfig AllConfig::get_location_host_config(const std::string &location_name)
{
	return (this->_location_config[location_name]);
}
