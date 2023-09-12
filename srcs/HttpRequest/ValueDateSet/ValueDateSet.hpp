#ifndef SRCS_HTTPREQUEST_VALUEDATESET_VALUEDATESET_HPP_
#define SRCS_HTTPREQUEST_VALUEDATESET_VALUEDATESET_HPP_

#include <string>
#include <iostream>
#include <sstream>
#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

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
	public:
		ValueDateSet();
		ValueDateSet(const ValueDateSet &other);
		ValueDateSet& operator=(const ValueDateSet &other);
		explicit ValueDateSet(const std::string &date_format);
		~ValueDateSet();
		std::string get_valuedateset_day_name() const;
		std::string get_valuedateset_day() const;
		std::string get_valuedateset_month() const;
		std::string get_valuedateset_year() const;
		std::string get_valuedateset_hour() const;
		std::string get_valuedateset_minute() const;
		std::string get_valuedateset_second() const;
		void show_value();
};

#endif  // SRCS_HTTPREQUEST_VALUEDATESET_VALUEDATESET_HPP_
