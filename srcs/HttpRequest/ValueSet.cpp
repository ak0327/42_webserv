#include "../includes/ValueSet.hpp"

ValueSet::ValueSet()
{
	this->_value = "";
}

ValueSet::~ValueSet()
{
	//nothing to do
}

void	ValueSet::set_value(const std::string &value)
{
	this->_value = value;
}

std::string ValueSet::get_value_set(void) const
{
	return (this->_value);
}