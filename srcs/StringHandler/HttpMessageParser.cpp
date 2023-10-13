#include <ctype.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"

namespace {

double get_integer_part(const std::string &str, size_t idx) {
	if (str.length() < idx) {
		return NG;
	}
	return StringHandler::to_digit(str[idx]);
}

double get_fractional_part(const std::string &str_after_decimal_point,
						   size_t *precision_idx) {
	double	digit, num;
	int		precision_num;
	size_t	idx;

	num = 0;
	digit = 1;
	idx = 0;
	while (isdigit(str_after_decimal_point[idx])) {
		precision_num = StringHandler::to_digit(str_after_decimal_point[idx]);
		num = num * 10 + precision_num;
		digit *= 10;
		++idx;
	}
	*precision_idx = idx;
	num /= digit;
	return num;
}

std::size_t count(const std::vector<std::string> &vec, const std::string &target) {
	return std::count(vec.begin(), vec.end(), target);
}

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

	if (0 < h || h < static_cast<int>(day_names.size())) {
		return std::string(EMPTY);
	}
	return day_names[h];
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

namespace HttpMessageParser {

bool is_printable(const std::string &str)
{
	std::size_t pos;

	pos = 0;
	while (str[pos])
	{
		if (!isprint(str[pos])) {
			return false;
		}
		++pos;
	}
	return true;
}

std::string obtain_word_before_delimiter(const std::string &field_value, const char &delimiter)
{
	return field_value.substr(0, field_value.find(delimiter));
}

std::string obtain_word_after_delimiter(const std::string &str, char delimiter)
{
	return str.substr(str.find(delimiter) + 1);
}

std::string	obtain_weight(const std::string &field_value)
{
	return (obtain_word_after_delimiter(field_value, '='));
}

std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (is_whitespace(field_value_with_ows[before_pos]) == true && before_pos != field_value_with_ows.length())
		++before_pos;
	while (is_whitespace(field_value_with_ows[after_pos]) == true && after_pos != 0)
		--after_pos;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}


// DIGIT = %x30-39; 10 進数字（ 0-9 ）
// sign, space is not allowed for Request message
int to_integer_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	int			num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stoi(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

// delta-seconds = 1*DIGIT
// The delta-seconds rule specifies a non-negative integer
int to_delta_seconds(const std::string &str, bool *succeed) {
	return to_integer_num(str, succeed);
}

long to_long_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	long		num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stol(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

long to_length(const std::string &str, bool *succeed) {
	return to_long_num(str, succeed);
}



// HTTP-version	= HTTP-name "/" DIGIT "." DIGIT
// qvalue = ( "0" [ "." 0*3DIGIT ] )
//        / ( "1" [ "." 0*3("0") ] )
//
//  1.234
//    ^^^ precision_digit = 3
double to_floating_num(const std::string &str,
										  size_t precision_digit,
										  bool *succeed) {
	bool		is_success;
	double 		num, precision_num;
	std::size_t	idx, precision_idx;

	is_success = false;
	if (succeed) { *succeed = is_success; }
	num = 0;
	idx = 0;
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = get_integer_part(str, idx);
	++idx;

	if (str[idx] != DECIMAL_POINT) {
		if (str[idx] == '\0') {
			is_success = true;
		}
		if (succeed) { *succeed = is_success; }
		return num;
	}
	++idx;

	precision_num = get_fractional_part(&str[idx], &precision_idx);
	num += precision_num;

	if (str[idx + precision_idx] == '\0' && precision_idx <= precision_digit) {
		is_success = true;
	}
	if (succeed) { *succeed = is_success; }
	return num;
}

// Delimiters : set of US-ASCII visual characters not allowed in a token
//  (DQUOTE and "(),/:;<=>?@[\]{}").
bool is_delimiters(char c) {
	return std::string(DELIMITERS).find(c) != std::string::npos;
}

// VCHAR = %x21-7E ; (any visible [USASCII] character).
bool is_vchar(char c) {
	return std::isprint(c);
}

// obs-text = %x80-FF
bool is_obs_text(char c) {
	int uc = static_cast<unsigned char>(c);

	return (0x80 <= uc && uc <= 0xFF);
}

// field-vchar = VCHAR / obs-text
bool is_field_vchar(char c) {
	return (is_vchar(c) || is_obs_text(c));
}

// field-content = field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]
bool is_field_content(const std::string &str) {
	std::size_t pos;

	pos = 0;
	if (!HttpMessageParser::is_vchar(str[pos])) {
		return false;
	}
	while (str[pos]) {
		while (HttpMessageParser::is_whitespace(str[pos])) {
			++pos;
		}
		if (!HttpMessageParser::is_field_vchar(str[pos])) {
			return false;
		}
		while (HttpMessageParser::is_field_vchar(str[pos])) {
			++pos;
		}
	}
	return true;
}

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//      / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//      / DIGIT / ALPHA
//      ; any VCHAR, except delimiters
bool is_tchar(char c) {
	if (!is_vchar(c)) {
		return false;
	}
	if (is_delimiters(c)) {
		return false;
	}
	return true;
}

// token = 1*tchar
bool is_token(const std::string &str) {
	std::size_t pos;

	pos = 0;
	while (str[pos]) {
		if (!is_tchar(str[pos])) {
			return false;
		}
		++pos;
	}
	return true;
}

bool is_whitespace(char c) {
	return c == SP || c == HT;
}

bool is_end_with_cr(const std::string &str) {
	return (!str.empty() && str[str.length() - 1] == CR);
}

bool is_valid_method(const std::string &method) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(METHODS.begin(), METHODS.end(), method);
	return itr != METHODS.end();
}

bool is_valid_request_target(const std::string &request_target) {
	return HttpMessageParser::is_printable(request_target);
}

bool is_valid_http_version(const std::string &http_version) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(HTTP_VERSIONS.begin(), HTTP_VERSIONS.end(), http_version);
	return itr != HTTP_VERSIONS.end();
}
Result<int, int> parse_http_date(const std::string &http_date,
								 std::string *day_name,
								 std::string *day,
								 std::string *month,
								 std::string *year,
								 std::string *hour,
								 std::string *minute,
								 std::string *second,
								 std::string *gmt) {
	std::size_t pos, end_pos;
	Result<std::string, int> day_name_result, day_result, month_result, year_result;
	Result<std::string, int> hour_result, minute_result, second_result, gmt_result;


	if (!day_name || !day || !month || !year || !hour || !minute || !second || !gmt) {
		return Result<int, int>::err(NG);
	}

	// day_name
	pos = 0;
	day_name_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COMMA, &end_pos);
	if (day_name_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// COMMA
	if (http_date[pos] != COMMA) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	/* day1 */
	// day
	day_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end_pos);
	if (day_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// month
	month_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end_pos);
	if (month_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// year
	year_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end_pos);
	if (year_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	/* time-of-day */
	// hour
	hour_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end_pos);
	if (hour_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// COLON
	if (http_date[pos] != COLON) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// minute
	minute_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end_pos);
	if (minute_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// COLON
	if (http_date[pos] != COLON) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// second
	second_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end_pos);
	if (second_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// GMT
	gmt_result = StringHandler::parse_pos_to_delimiter(http_date, pos, '\0', NULL);
	if (gmt_result.is_err()) {
		return Result<int, int>::err(NG);
	}

	*day_name = day_name_result.get_ok_value();
	*day = day_result.get_ok_value();
	*month = month_result.get_ok_value();
	*year = year_result.get_ok_value();
	*hour = hour_result.get_ok_value();
	*minute = minute_result.get_ok_value();
	*second = second_result.get_ok_value();
	*gmt = gmt_result.get_ok_value();

	return Result<int, int>::ok(OK);
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

Result<int, int> validate_http_date(const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt) {
	int day_num, month_num, year_num, hour_num, minute_num, second_num;
	std::vector<std::string>::const_iterator month_itr;
	bool succeed;

	// day1
	day_num = to_integer_num(day, &succeed);
	if (day.length() != 2 || !succeed) {
		return Result<int, int>::err(NG);
	}

	month_itr = std::find(MONTHS.begin(), MONTHS.end(), month);
	if (month_itr == MONTHS.end()) {
		return Result<int, int>::err(NG);
	}
	month_num = static_cast<int>(std::distance(MONTHS.begin(), month_itr)) + 1;

	year_num = to_integer_num(year, &succeed);
	if (year.length() != 4 || !succeed) {
		return Result<int, int>::err(NG);
	}

	if (!is_valid_day1(year_num, month_num, day_num)) {
		return Result<int, int>::err(NG);
	}

	// time-of-date
	hour_num = to_integer_num(hour, &succeed);
	if (hour.length() != 2 || !succeed) {
		return Result<int, int>::err(NG);
	}

	minute_num = to_integer_num(minute, &succeed);
	if (minute.length() != 2 || !succeed) {
		return Result<int, int>::err(NG);
	}

	second_num = to_integer_num(second, &succeed);
	if (second.length() != 2 || !succeed) {
		return Result<int, int>::err(NG);
	}

	if (!is_valid_time_of_day(hour_num, minute_num, second_num)) {
		return Result<int, int>::err(NG);
	}

	// day_name
	if (std::find(DAY_NAMES.begin(), DAY_NAMES.end(), day_name) == DAY_NAMES.end()) {
		return Result<int, int>::err(NG);
	}
	if (!is_valid_day_name(day_name, year_num, month_num, day_num)) {
		return Result<int, int>::err(NG);
	}

	// gmt
	if (gmt != std::string(GMT)) {
		return Result<int, int>::err(NG);
	}

	return Result<int, int>::ok(OK);
}

}  // namespace HttpMessageParser
