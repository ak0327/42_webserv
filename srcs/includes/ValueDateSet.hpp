#ifndef VALUEDATESET_HPP
#define VALUEDATESET_HPP

#include <string>

#include "BaseKeyValueMap.hpp"

class ValueDateSet: public BaseKeyValueMap
{
	private:
		std::string	_day_name;
		std::string _day;
		std::string _month;
		std::string _year;
		std::string _hour;
		std::string _minute;
		std::string _second;

		ValueDateSet();
		ValueDateSet(const ValueDateSet &other);
		ValueDateSet& operator=(const ValueDateSet &other);

	public:
		ValueDateSet();
		ValueDateSet(const ValueDateSet &other);
		ValueDateSet& operator=(const ValueDateSet &other);
		ValueDateSet(const std::string &date_format);
		~ValueDateSet();

		std::string get_valuedateset_day_name();
		std::string get_valuedateset_day();
		std::string get_valuedateset_month();
		std::string get_valuedateset_year();
		std::string get_valuedateset_hour();
		std::string get_valuedateset_minute();
		std::string get_valuedateset_second();
};

#endif