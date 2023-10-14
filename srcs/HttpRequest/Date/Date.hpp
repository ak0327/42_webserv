#pragma once

# include <string>
# include "Constant.hpp"
# include "FieldValues.hpp"
# include "Result.hpp"

class Date : public FieldValues {
 public:
	explicit Date(const std::string &http_date);
	Date(const Date &other);
	Date &operator=(const Date &rhs);
	virtual ~Date();

	std::string get_day_name() const;
	std::string get_day() const;
	std::string get_month() const;
	std::string get_year() const;
	std::string get_hour() const;
	std::string get_minute() const;
	std::string get_second() const;
	std::string get_gmt() const;
	date_format get_format() const;
	bool is_ok() const;
	bool is_err() const;

 private:
	std::string	_day_name;
	std::string _day;
	std::string _month;
	std::string _year;
	std::string _hour;
	std::string _minute;
	std::string _second;
	std::string _gmt;
	date_format _format;
	Result<int, int> _result;
};
