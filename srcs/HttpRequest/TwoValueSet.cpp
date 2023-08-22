#include "../includes/TwoValueSet.hpp"

TwoValueSet::TwoValueSet()
{
	this->_firstvalue = "";
	this->_secondValue = "";
}

TwoValueSet::~TwoValueSet()
{

}

void TwoValueSet::set_values(const std::string &first_value, const std::string &second_value)
{
	this->_firstvalue = first_value;
	this->_secondValue = second_value;
}

void TwoValueSet::set_values(const std::string &first_value)
{
	this->_firstvalue = first_value;
}

std::string TwoValueSet::get_firstvalue(void) const
{
	return (this->_firstvalue);
}

std::string TwoValueSet::get_secondvalue(void) const
{
	return (this->_secondValue);
}