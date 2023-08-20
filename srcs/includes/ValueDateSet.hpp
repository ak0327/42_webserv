#ifndef VALUEDATESET_HPP
#define VALUEDATESET_HPP

#include <string>

class ValueDateSet
{
	private:
		std::string	_day_name;
		std::string _day;
		std::string _month;
		std::string _year;
		std::string _hour;
		std::string _hour;
		std::string _minute;
		std::string _second;

		ValueDateSet(const ValueDateSet &other);
		ValueDateSet& operator=(const ValueDateSet &other);

	public:
		ValueDateSet();
		ValueDateSet(const std::string &value);
};

#endif