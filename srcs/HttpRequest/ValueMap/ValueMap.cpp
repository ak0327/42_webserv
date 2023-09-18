#include "ValueMap.hpp"

ValueMap::ValueMap():BaseKeyValueMap(){}

ValueMap::ValueMap(const std::string &value, std::map<std::string, std::string> value_map):BaseKeyValueMap()
{
	this->_only_value = value;
	this->_value_map = value_map;
}

ValueMap::ValueMap(std::map<std::string, std::string> value_map)
{
	this->_value_map = value_map;
}

ValueMap::ValueMap(const ValueMap &other):BaseKeyValueMap(other)
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

ValueMap::~ValueMap(){}

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

void ValueMap::show_value()
{
	std::cout << "one value is >> " << this->_only_value;
	std::cout << "map are ";
	std::map<std::string, std::string>::iterator now_it = this->_value_map.begin();
	while (now_it != this->_value_map.end())
	{
		std::cout << now_it->first << " " << now_it->second << " | ";
		now_it++;
	}
	std::cout << std::endl;
}
