#include <iostream>
#include "Constant.hpp"
#include "Color.hpp"
#include "Date.hpp"
#include "HttpMessageParser.hpp"

Date::Date(const std::string &http_date) {
	std::string day_name, day, month, year, hour, minute, second, gmt;
	Result<date_format, int> parse_result;
	Result<int, int> validate_result;
	date_format format;

	parse_result = HttpMessageParser::parse_http_date(http_date,
													  &day_name,
													  &day, &month, &year,
													  &hour, &minute, &second,
													  &gmt);
	if (parse_result.is_err()) {
		this->_result = Result<int, int>::err(ERR);
		return;
	}
	format = parse_result.get_ok_value();

	validate_result = HttpMessageParser::validate_http_date(format,
															day_name,
															day, month, year,
															hour, minute, second,
															gmt);
	if (validate_result.is_err()) {
		this->_result = Result<int, int>::err(ERR);
		return;
	}

	this->_day_name = day_name;
	this->_day = day;
	this->_month = month;
	this->_year = year;
	this->_hour = hour;
	this->_minute = minute;
	this->_second = second;
	this->_gmt = gmt;
	this->_format = format;

	this->_result = Result<int, int>::ok(OK);
}

Date::Date(const Date &other) {
	*this = other;
}

Date &Date::operator=(const Date &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_day_name = rhs._day_name;
	this->_day = rhs._day;
	this->_month = rhs._month;
	this->_year = rhs._year;
	this->_hour = rhs._hour;
	this->_minute = rhs._minute;
	this->_second = rhs._second;
	this->_gmt = rhs._gmt;
	this->_result = rhs._result;
	return (*this);
}

Date::~Date() {}

std::string Date::get_day_name() const { return this->_day_name; }
std::string Date::get_day() const { return this->_day; }
std::string Date::get_month() const { return this->_month; }
std::string Date::get_year() const { return this->_year; }
std::string Date::get_hour() const { return this->_hour; }
std::string Date::get_minute() const { return this->_minute; }
std::string Date::get_second() const { return this->_second; }
std::string Date::get_gmt() const { return this->_gmt; }
date_format Date::get_format() const { return this->_format; }
bool Date::is_ok() const { return this->_result.is_ok(); }
bool Date::is_err() const { return this->_result.is_err(); }
