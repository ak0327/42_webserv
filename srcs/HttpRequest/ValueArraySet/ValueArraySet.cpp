#include "ValueArraySet.hpp"

ValueArraySet::ValueArraySet():BaseKeyValueMap(){}

ValueArraySet::ValueArraySet(const ValueArraySet &other):BaseKeyValueMap(other)
{
	this->_value_array = other.get_value_array();
}

ValueArraySet::ValueArraySet(const std::vector<std::string> &value_array)
{
	this->_value_array = value_array;
}

ValueArraySet& ValueArraySet::operator=(const ValueArraySet &other)
{
	if (this == &other)
		return (*this);
	this->_value_array = other.get_value_array();
	return (*this);
}

ValueArraySet::~ValueArraySet(){}

std::vector<std::string>	ValueArraySet::get_value_array(void) const
{
	return (this->_value_array);
}
