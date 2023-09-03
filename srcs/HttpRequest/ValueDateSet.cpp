#include "../includes/ValueDateSet.hpp"

ValueDateSet::ValueDateSet()
{

}

ValueDateSet& ValueDateSet::operator=(const ValueDateSet &other)
{
	if (this == &other)
		return (*this);
	this->_day_name = other.get_valuedateset_day_name();
	this->_day = other.get_valuedateset_day();
	this->_month = other.get_valuedateset_month();
	this->_year = other.get_valuedateset_year();
	this->_hour = other.get_valuedateset_hour();
	this->_minute = other.get_valuedateset_minute();
	this->_second = other.get_valuedateset_second();
	return (*this);
}

ValueDateSet::ValueDateSet(const std::string &date_format)
{
	std::stringstream	ss(date_format);
	std::string			line;

	std::getline(ss, this->_day_name, ',');
	std::getline(ss, line, ',');

	std::stringstream	sss(line);
	std::getline(sss, this->_day, ' ');
	std::getline(sss, this->_month, ' ');
	std::getline(sss, this->_year, ' ');

	std::string			hour_minute_second;
	std::getline(sss, hour_minute_second, ' ');

	std::stringstream	ssss(hour_minute_second);
	std::getline(ssss, this->_hour, ':');
	std::getline(ssss, this->_minute, ':');
	std::getline(ssss, this->_second, ':');
}

ValueDateSet::~ValueDateSet()
{
	
}

std::string ValueDateSet::get_valuedateset_day_name() const
{
	return (this->_day_name);
}

std::string ValueDateSet::get_valuedateset_day() const
{
	return (this->_day);
}

std::string ValueDateSet::get_valuedateset_month() const
{
	return (this->_month);
}

std::string ValueDateSet::get_valuedateset_year() const
{
	return (this->_year);
}

std::string ValueDateSet::get_valuedateset_hour() const
{
	return (this->_hour);
}

std::string ValueDateSet::get_valuedateset_minute() const
{
	return (this->_minute);
}

std::string ValueDateSet::get_valuedateset_second() const
{
	return (this->_second);
}