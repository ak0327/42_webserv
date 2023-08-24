#include "../includes/ValueDateSet.hpp"

ValueDateSet::ValueDateSet()
{

}

ValueDateSet::~ValueDateSet()
{
	
}

void	ValueDateSet::ready_valuedateset(const std::string &value)
{
	this->_day_name = "";
	this->_day = "";
	this->_month = "";
	this->_year = "";
	this->_hour = "";
	this->_minute = "";
	this->_second = "";
}