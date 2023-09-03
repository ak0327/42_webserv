#include "../includes/ValueMap.hpp"

ValueMap::ValueMap()
{

}

ValueMap::ValueMap(std::map<std::string, std::string> value_map)
{
	this->_value_map = value_map;
}

ValueMap::ValueMap(const ValueMap &other)
{
	this->_value_map = other.get_value_map();
}

ValueMap& ValueMap::operator=(const ValueMap &other)
{
	if (this == &other)
		return (*this);
	this->_value_map = other.get_value_map();
	return (*this);
}

ValueMap::~ValueMap()
{

}

void	ValueMap::set_value(const std::string &only_value, const std::map<std::string, std::string> &value_map)
{
	this->_only_value = only_value;
	this->_value_map = value_map;
}

void	ValueMap::set_value(const std::string &only_value)
{
	this->_only_value = only_value;
}

void	ValueMap::set_value(const std::map<std::string, std::string> &value_map)
{
	this->_value_map = value_map;
}

std::string ValueMap::get_only_value(void) const
{
	return (this->_only_value);
}

std::map<std::string, std::string>	ValueMap::get_value_map(void) const
{
	return (this->_value_map);
}