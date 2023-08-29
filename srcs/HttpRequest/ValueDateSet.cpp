#include "../includes/ValueDateSet.hpp"

ValueDateSet::ValueDateSet(const std::string &date_format)
{
	//分割するための方法を書く
	this->_year = date_format;
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