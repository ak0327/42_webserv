#include "../includes/ValueDateSet.hpp"

ValueDateSet::ValueDateSet(const std::string &date_format)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(all_value);
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