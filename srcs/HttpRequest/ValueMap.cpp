#include "../includes/ValueMap.hpp"

ValueMap::ValueMap()
{

}

ValueMap::~ValueMap()
{

}

void	ValueMap::set_value(const std::string &only_value, const std::map<std::string, std::string> &value_map)
{
	this->_only_value = only_value;
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