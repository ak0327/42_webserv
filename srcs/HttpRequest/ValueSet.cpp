#include "../includes/ValueSet.hpp"

ValueSet::ValueSet(const std::string &value)
{
	this->_value = value;
}

ValueSet::~ValueSet()
{
	//nothing to do
}

std::string ValueSet::get_value_set(void) const
{
	return (this->_value);
}