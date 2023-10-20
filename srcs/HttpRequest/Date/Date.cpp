#include <algorithm>
#include <iostream>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Date.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

namespace {

// Zeller's congruence
std::string calculate_day_name(int year, int month, int day) {
	if (month < 3) {
		month += 12;
		year -= 1;
	}
	int c = year / 100;
	int y = year % 100;
	int h = (day + 13 * (month + 1) / 5 + y + y / 4 + 5 * c + c / 4) % 7;

	std::vector<std::string> day_names;
	day_names.push_back(std::string(SAT));
	day_names.push_back(std::string(SUN));
	day_names.push_back(std::string(MON));
	day_names.push_back(std::string(TUE));
	day_names.push_back(std::string(WED));
	day_names.push_back(std::string(THU));
	day_names.push_back(std::string(FRI));

	if (h < 0 || static_cast<int>(day_names.size()) <= h) {
		return std::string(EMPTY);
	}
	return day_names[h];
}


bool is_leap_year(int year) {
	if (year % 4 != 0) {
		return false;
	}
	if (year % 100 == 0 && year % 400 != 0) {
		return false;
	}
	return true;
}

bool is_valid_day1(int year, int month, int day) {
	int month_idx;
	int days_in_month[12];
	const int jan_idx = 0, feb_idx = 1, mar_idx = 2, apr_idx = 3,
			may_idx = 4, jun_idx = 5, jul_idx = 6, aug_idx = 7,
			sep_idx = 8, oct_idx = 9, nov_idx = 10, dec_idx = 11;

	if (year < GREGORIAN_CALENDAR || month < 1 || 12 < month) {
		return false;
	}
	month_idx = month - 1;

	days_in_month[jan_idx] = 31;
	days_in_month[feb_idx] = is_leap_year(year) ? 29 : 28;
	days_in_month[mar_idx] = 31;
	days_in_month[apr_idx] = 30;
	days_in_month[may_idx] = 31;
	days_in_month[jun_idx] = 30;
	days_in_month[jul_idx] = 31;
	days_in_month[aug_idx] = 31;
	days_in_month[sep_idx] = 30;
	days_in_month[oct_idx] = 31;
	days_in_month[nov_idx] = 30;
	days_in_month[dec_idx] = 31;

	return 1 <= day && day <= days_in_month[month_idx];
}

bool is_valid_time_of_day(int hour, int minute, int second) {
	if (hour < 0 || 23 < hour) {
		return false;
	}
	if (minute < 0 || 59 <minute) {
		return false;
	}
	if (second < 0 || 59 < second) {
		return false;
	}
	return true;
}

bool is_valid_day_name(const std::string &day_name, int year, int month, int day) {
	std::string zellers_day_name = calculate_day_name(year, month, day);

	return day_name == zellers_day_name;
}

Result <int, int> to_integer_valid_day1_str(const std::string &day,
											const std::string &month,
											const std::string &year,
											int *day_num,
											int *month_num,
											int *year_num) {
	std::vector<std::string>::const_iterator month_itr;
	bool succeed;

	if (!day_num || !month_num || !year_num) {
		return Result<int, int>::err(ERR);
	}
	*day_num = HttpMessageParser::to_integer_num(day, &succeed);
	if (day.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	month_itr = std::find(MONTHS.begin(), MONTHS.end(), month);
	if (month_itr == MONTHS.end()) {
		return Result<int, int>::err(ERR);
	}
	*month_num = static_cast<int>(std::distance(MONTHS.begin(), month_itr)) + 1;

	*year_num = HttpMessageParser::to_integer_num(year, &succeed);
	if (year.length() != 4 || !succeed) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result <int, int> to_integer_valid_time_of_day_str(const std::string &hour,
												   const std::string &minute,
												   const std::string &second,
												   int *hour_num,
												   int *minute_num,
												   int *second_num) {
	bool succeed;

	*hour_num = HttpMessageParser::to_integer_num(hour, &succeed);
	if (hour.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	*minute_num = HttpMessageParser::to_integer_num(minute, &succeed);
	if (minute.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	*second_num = HttpMessageParser::to_integer_num(second, &succeed);
	if (second.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}


Result <int, int> validate_imf_fixdate(const std::string &day_name,
									   const std::string &day,
									   const std::string &month,
									   const std::string &year,
									   const std::string &hour,
									   const std::string &minute,
									   const std::string &second,
									   const std::string &gmt) {
	int day_num, month_num, year_num, hour_num, minute_num, second_num;
	Result<int, int> day1_result, time_of_day_result;

	// day1
	day1_result = to_integer_valid_day1_str(day, month, year,
											&day_num, &month_num, &year_num);
	if (day1_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	if (!is_valid_day1(year_num, month_num, day_num)) {
		return Result<int, int>::err(ERR);
	}

	// time-of-date
	time_of_day_result = to_integer_valid_time_of_day_str(hour, minute, second,
														  &hour_num, &minute_num, &second_num);
	if (time_of_day_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	if (!is_valid_time_of_day(hour_num, minute_num, second_num)) {
		return Result<int, int>::err(ERR);
	}

	// day_name
	if (std::find(DAY_NAMES.begin(), DAY_NAMES.end(), day_name) == DAY_NAMES.end()) {
		return Result<int, int>::err(ERR);
	}
	if (!is_valid_day_name(day_name, year_num, month_num, day_num)) {
		return Result<int, int>::err(ERR);
	}

	// gmt
	if (gmt != std::string(GMT)) {
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

Result<int, int> validate_http_date(date_format format,
									const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt) {
	Result<int, int> validate_result;

	if (format == IMF_FIXDATE) {
		validate_result = validate_imf_fixdate(day_name,
											   day, month, year,
											   hour, minute, second,
											   gmt);
	}
	// else if (format == RFC850_DATE) {
	// 	// todo
	// } else {
	// 	// todo
	// }

	if (validate_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

/*
  day-name     = %s"Mon" / %s"Tue" / %s"Wed"
               / %s"Thu" / %s"Fri" / %s"Sat" / %s"Sun"

  date1        = day SP month SP year
               ; e.g., 02 Jun 1982

  day          = 2DIGIT
  month        = %s"Jan" / %s"Feb" / %s"Mar" / %s"Apr"
               / %s"May" / %s"Jun" / %s"Jul" / %s"Aug"
               / %s"Sep" / %s"Oct" / %s"Nov" / %s"Dec"
  year         = 4DIGIT
 */
Result<int, int> parse_date1(const std::string &http_date,
							 std::string *day,
							 std::string *month,
							 std::string *year,
							 std::size_t start_pos,
							 std::size_t *end_pos) {
	Result<std::string, int> day_result, month_result, year_result;
	std::size_t pos, end;

	if (!day || !month || !year || !end_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	day_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (day_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*day = day_result.get_ok_value();
	pos = end;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	month_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (month_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*month = month_result.get_ok_value();
	pos = end;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	year_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (year_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*year = year_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
  time-of-day  = hour ":" minute ":" second
               ; 00:00:00 - 23:59:60 (leap second)

  hour         = 2DIGIT
  minute       = 2DIGIT
  second       = 2DIGIT
 */
Result<int, int> parse_time_of_day(const std::string &http_date,
								   std::string *hour,
								   std::string *minute,
								   std::string *second,
								   std::size_t start_pos,
								   std::size_t *end_pos) {
	Result<std::string, int> hour_result, minute_result, second_result;
	std::size_t pos, end;

	if (!hour || !minute || !second || !end_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	hour_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end);
	if (hour_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*hour = hour_result.get_ok_value();
	pos = end;

	if (http_date[pos] != COLON) { return Result<int, int>::err(ERR); }
	pos++;

	minute_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end);
	if (minute_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*minute = minute_result.get_ok_value();
	pos = end;

	if (http_date[pos] != COLON) { return Result<int, int>::err(ERR); }
	pos++;

	second_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (second_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*second = second_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
 IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
  ; fixed length/zone/capitalization subset of the format
  ; see Section 3.3 of [RFC5322]

  IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT

 GMT          = %s"GMT"
 */
Result<int, int> parse_imf_fixdate(const std::string &http_date,
								   std::string *day_name,
								   std::string *day,
								   std::string *month,
								   std::string *year,
								   std::string *hour,
								   std::string *minute,
								   std::string *second,
								   std::string *gmt) {
	std::size_t pos, end_pos;
	Result<std::string, int> day_name_result, gmt_result;
	Result<int, int> day1_result, time_of_day_result;

	if (!day_name || !day || !month || !year || !hour || !minute || !second || !gmt) {
		return Result<int, int>::err(ERR);
	}

	pos = 0;
	day_name_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COMMA, &end_pos);
	if (day_name_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*day_name = day_name_result.get_ok_value();
	pos = end_pos;

	if (http_date[pos] != COMMA) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	day1_result = parse_date1(http_date, day, month, year, pos, &end_pos);
	if (day1_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	pos = end_pos;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	time_of_day_result = parse_time_of_day(http_date, hour, minute, second, pos, &end_pos);
	if (time_of_day_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	// GMT
	gmt_result = StringHandler::parse_pos_to_delimiter(http_date, pos, '\0', &end_pos);
	if (gmt_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*gmt = gmt_result.get_ok_value();

	return Result<int, int>::ok(OK);
}

/*
 Date = HTTP-date

 HTTP-date    = IMF-fixdate / obs-date

 obs-date     = rfc850-date / asctime-date
  rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT

  day-name-l   = %s"Monday" / %s"Tuesday" / %s"Wednesday"
               / %s"Thursday" / %s"Friday" / %s"Saturday"
               / %s"Sunday"

  date2        = day "-" month "-" 2DIGIT
               ; e.g., 02-Jun-82

  asctime-date = day-name SP date3 SP time-of-day SP year
  date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
               ; e.g., Jun  2

 https://www.rfc-editor.org/rfc/rfc9110#field.date
 */
Result<date_format, int> parse_http_date(const std::string &http_date,
										 std::string *day_name,
										 std::string *day,
										 std::string *month,
										 std::string *year,
										 std::string *hour,
										 std::string *minute,
										 std::string *second,
										 std::string *gmt) {
	Result<int, int> imf_fixdate_result;
	// Result<int, int> rfc850_date_result, asctime_date_result;  // todo

	imf_fixdate_result = parse_imf_fixdate(http_date,
										   day_name,
										   day, month, year,
										   hour, minute, second,
										   gmt);
	if (imf_fixdate_result.is_ok()) {
		return Result<date_format, int>::ok(IMF_FIXDATE);
	}

	// todo: parse_rfc850_date()
	// todo: parse_asctime_date()

	return Result<date_format, int>::err(ERR);
}


}  // namespace

// todo: end_pos
Date::Date(const std::string &http_date) {
	std::string day_name, day, month, year, hour, minute, second, gmt;
	Result<date_format, int> parse_result;
	Result<int, int> validate_result;
	date_format format;

	parse_result = parse_http_date(http_date,
								   &day_name,
								   &day, &month, &year,
								   &hour, &minute, &second,
								   &gmt);
	if (parse_result.is_err()) {
		this->_result = Result<int, int>::err(ERR);
		return;
	}
	format = parse_result.get_ok_value();

	validate_result = validate_http_date(format,
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
