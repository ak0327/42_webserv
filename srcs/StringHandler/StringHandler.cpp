#include "StringHandler.hpp"

#include <ctype.h>
#include <float.h>
#include <algorithm>
#include <cctype>
#include <climits>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "Color.hpp"

namespace {

bool is_in_int_range(int before_x10_num,
					 int add_num) {
	int max_div, max_mod;

	if (before_x10_num == INT_MAX || before_x10_num == INT_MIN) {
		return false;
	}
	if (before_x10_num > 0) {
		max_div = INT_MAX / 10;
		max_mod = INT_MAX % 10;
	} else {
		max_div = -(INT_MIN / 10);
		max_mod = -(INT_MIN % 10);
	}
	if (std::abs(before_x10_num) < max_div) {
		return true;
	}
	if (std::abs(before_x10_num) == max_div && max_mod == add_num) {
		return true;
	}
	return false;
}

double get_integer_part(const std::string &str, size_t idx) {
	if (str.length() < idx) {
		return 0;  // todo: ng case
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
		idx++;
	}
	*precision_idx = idx;
	num /= digit;
	return num;
}

}  // namespace


namespace StringHandler {

bool	is_end_with_cr(const std::string &value)
{
	if (value.length() <= 1)
		return (false);
	return (!value.empty() && value[value.length() - 1] == '\r');
}

bool	is_positive_under_intmax_double(const std::string &value)
{
	size_t				dot_counter = 0;
	size_t				now_pos = 0;
	size_t				value_length = value.length();
	std::istringstream	ss(value);
	double				value_to_double;

	if (value.find('.') == std::string::npos)
		return (false);
	while (now_pos != value_length)
	{
		if (value[now_pos] == '.')
		{
			dot_counter++;
			now_pos++;
		}
		if (!(std::isdigit(value[now_pos])))
			return (false);
		now_pos++;
	}
	if (dot_counter > 1)
		return (false);
	if (ss >> value_to_double)
	{
		if (value_to_double < 0)
			return (false);
		if (value_to_double <= INT_MAX)
			return (true);
		else
			return (false);
	}
	else
		return (false);
	return (true);
}

bool is_quoted(const std::string &value) {
	std::size_t head, tail;

	if (std::count(value.begin(), value.end(), '"') != 2) {
		return false;
	}
	head = value.find('"');
	tail = value.rfind('"');
	return head == 0 && tail + 1 == value.length();
}

bool	is_endl_semicolon_and_no_inner_semicoron(const std::string &word)
{
	size_t	pos = 0;
	size_t	semicolon_count = 0;

	while (word[pos] != '\0')
	{
		if (word[pos] == ';')
			semicolon_count++;
		pos++;
	}
	if (semicolon_count != 1)
		return (false);
	if (word[pos - 1] != ';')
		return (false);
	return (true);
}

bool is_ows(const char &c)
{
	return c == ' ' || c == '\t';
}

bool	is_printable_content(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	pos = 0;

	while (pos != value_length)
	{
		if (isprint(value[pos]) == false)
			return (false);
		pos++;
	}
	return (true);
}

bool	is_positive_and_under_intmax(const std::string &num_str)
{
	size_t	pos = 0;

	while (num_str[pos] != '\0')
	{
		if (std::isdigit(num_str[pos]) == false)
			return (false);
		pos++;
	}
	std::istringstream	iss(num_str);
	size_t				result;
	iss >> result;
	if (result > INT_MAX)
		return (false);
	return (true);
}

double str_to_double(const std::string &num_str)
{
	std::istringstream iss(num_str);
    double result;

    iss >> result;
    return result;
}

int to_digit(const char &c)
{
	return (c - '0');
}

int	str_to_int(const std::string &word)
{
	size_t	pos = 0;
	int		num = 0;

	while (word[pos] != '\0')
	{
		num = num * 10 + to_digit(word[pos]);
		pos++;
	}
	return (num);
}

std::string	skip_lastsemicolon(const std::string &word)
{
	return word.substr(0, word.find(';'));
}

std::string int_to_str(int num)
{
	std::string result;

	if (num == 0)
		return "0";
	while (num > 0)
	{
		result += static_cast<char>(toascii(num % 10));
		num /= 10;
	}
	return result;
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

std::string obtain_unquote_str(const std::string &quoted_str)
{
	return quoted_str.substr(1, quoted_str.length() - 2);
}

std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (is_ows(field_value_with_ows[before_pos]) == true && before_pos != field_value_with_ows.length())
		before_pos++;
	while (is_ows(field_value_with_ows[after_pos]) == true && after_pos != 0)
		after_pos--;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}

////////////////////////////////////////////////////////////////////////////////

int stoi(const std::string &str, std::size_t *idx, bool *overflow) {
	std::size_t	i;
	int 		num;
	int			digit, sign;

	if (overflow) { *overflow = false; }
	if (idx) { *idx = 0; }
	i = 0;
	while (std::isspace(str[i])) {
		i++;
	}
	sign = 1;
	if (str[i] == '+' || str[i] == '-') {
		if (str[i] == '-') {
			sign = -1;
		}
		i++;
	}
	num = 0;
	while (std::isdigit(str[i])) {
		digit = to_digit(str[i]);
		if (!is_in_int_range(num, digit)) {
			if (sign == 1) {
				num = INT_MAX;
			} else {
				num = INT_MIN;
			}
			if (overflow) { *overflow = true; }
			if (idx) { *idx = i; }
			return num;
		}
		digit *= sign;
		num = num * 10 + digit;
		i++;
	}
	if (idx) { *idx = i; }
	return num;
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
	num = StringHandler::stoi(str, &idx, &is_overflow);  // todo: int? long?
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
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
		// printf(CYAN "!isdigit\n" RESET);
		return num;
	}
	num = get_integer_part(str, idx);
	idx++;

	if (str[idx] != '.') {
		if (str[idx] == '\0') {
			is_success = true;
		}
		if (succeed) { *succeed = is_success; }
		// printf(CYAN "str[idx] != ., num:%lf\n" RESET, num);
		return num;
	}
	idx++;

	precision_num = get_fractional_part(&str[idx], &precision_idx);
	// printf(CYAN "num:%lf, prec_num:%lf, prec_idx:%zu\n" RESET, num, precision_num, precision_idx);
	num += precision_num;

	if (str[idx + precision_idx] == '\0' && precision_idx <= precision_digit) {
		is_success = true;
	}
	if (succeed) { *succeed = is_success; }
	return num;
}


}  // namespace StringHandler

