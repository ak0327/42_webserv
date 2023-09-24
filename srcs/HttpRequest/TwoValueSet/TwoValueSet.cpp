#include "TwoValueSet.hpp"

TwoValueSet::TwoValueSet():BaseKeyValueMap(){}

TwoValueSet::TwoValueSet(std::string const &first_value)
{
	this->_firstvalue = first_value;
}

TwoValueSet::TwoValueSet(const std::string &first_value, const std::string &second_value)
{
	this->_firstvalue = first_value;
	this->_secondValue = second_value;
}

TwoValueSet& TwoValueSet::operator=(const TwoValueSet &other)
{
	if (this == &other)
		return (*this);
	this->_firstvalue = other.get_firstvalue();
	this->_secondValue = other.get_secondvalue();

	return (*this);
}

TwoValueSet::~TwoValueSet(){}

std::string TwoValueSet::get_firstvalue(void) const
{
	return (this->_firstvalue);
}

std::string TwoValueSet::get_secondvalue(void) const
{
	return (this->_secondValue);
}
