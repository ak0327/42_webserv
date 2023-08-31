#include "../includes/ValueDateSet.hpp"

ValueDateSet::ValueDateSet(const std::string &date_format)
{
	//分割するための方法を書く
	this->_year = date_format;
	this->_day = "";
	this->_month = "";
	this->_year = "";
	this->_hour = "";
	this->_minute = "";
	this->_second = "";
}

ValueDateSet::~ValueDateSet()
{
	
}

std::string ValueDateSet::get_valuedateset_day_name()
{
	return (this->_day_name);
}

std::string ValueDateSet::get_valuedateset_day()
{
	return (this->_day);
}

std::string ValueDateSet::get_valuedateset_month()
{
	return (this->_month);
}

std::string ValueDateSet::get_valuedateset_year()
{
	return (this->_year);
}

std::string ValueDateSet::get_valuedateset_hour()
{
	return (this->_hour);
}

std::string ValueDateSet::get_valuedateset_minute()
{
	return (this->_minute);
}

std::string ValueDateSet::get_valuedateset_second()
{
	return (this->_second);
}