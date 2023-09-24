#include "ValueSet.hpp"

ValueSet::ValueSet():BaseKeyValueMap(){}

ValueSet::ValueSet(const ValueSet &other):BaseKeyValueMap()
{
	this->_value = other.get_value_set();
}

ValueSet& ValueSet::operator=(const ValueSet &other)
{
	if (this == &other)
		return (*this);
	this->_value = other.get_value_set();
	return (*this);
}

ValueSet::ValueSet(const std::string &value)
{
	this->_value = value;
}

ValueSet::~ValueSet(){}

std::string ValueSet::get_value_set(void) const
{
	return (this->_value);
}
