#include <ctype.h>
#include <algorithm>
#include <climits>
#include <iostream>
#include <limits>
#include <sstream>
#include "Color.hpp"
#include "Constant.hpp"
#include "StringHandler.hpp"
#include "HttpMessageParser.hpp"


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

bool is_in_long_range(long before_x10_num,
					  long add_num) {
	long max_div, max_mod;

	if (before_x10_num == LONG_MAX || before_x10_num == LONG_MIN) {
		return false;
	}
	if (before_x10_num > 0) {
		max_div = LONG_MAX / 10;
		max_mod = LONG_MAX % 10;
	} else {
		max_div = -(LONG_MIN / 10);
		max_mod = -(LONG_MIN % 10);
	}
	if (std::abs(before_x10_num) < max_div) {
		return true;
	}
	if (std::abs(before_x10_num) == max_div && max_mod == add_num) {
		return true;
	}
	return false;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

namespace StringHandler {

int to_digit(const char &c) {
	return (c - '0');
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

bool is_quoted(const std::string &value) {
	std::size_t head, tail;

	if (std::count(value.begin(), value.end(), '"') != 2) {
		return false;
	}
	head = value.find('"');
	tail = value.rfind('"');
	return head == 0 && tail + 1 == value.length();
}

bool is_endl_semicolon_and_no_inner_semicoron(const std::string &word) {
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

int stoi(const std::string &str, std::size_t *idx, bool *overflow) {
	std::size_t	i;
	int 		num, digit, sign;

	if (overflow) { *overflow = false; }
	if (idx) { *idx = 0; }

	i = 0;
	while (std::isspace(str[i])) {
		i++;
	}

	sign = 1;
	if (str[i] == SIGN_PLUS || str[i] == SIGN_MINUS) {
		if (str[i] == SIGN_MINUS) {
			sign = -1;
		}
		i++;
	}

	num = 0;
	while (std::isdigit(str[i])) {
		digit = to_digit(str[i]);
		if (!is_in_int_range(num, digit)) {
			num = (sign == 1) ? INT_MAX : INT_MIN;
			if (overflow) { *overflow = true; }
			if (idx) { *idx = i; }
			return num;
		}
		num = num * 10 + sign * digit;
		i++;
	}

	if (idx) { *idx = i; }
	return num;
}

long stol(const std::string &str, std::size_t *idx, bool *overflow) {
	std::size_t	i;
	long 		num;
	int			digit, sign;

	if (overflow) { *overflow = false; }
	if (idx) { *idx = 0; }

	i = 0;
	while (std::isspace(str[i])) {
		i++;
	}

	sign = 1;
	if (str[i] == SIGN_PLUS || str[i] == SIGN_MINUS) {
		if (str[i] == SIGN_MINUS) {
			sign = -1;
		}
		i++;
	}

	num = 0;
	while (std::isdigit(str[i])) {
		digit = to_digit(str[i]);
		if (!is_in_long_range(num, digit)) {
			num = (sign == 1) ? LONG_MAX : LONG_MIN;
			if (overflow) { *overflow = true; }
			if (idx) { *idx = i; }
			return num;
		}
		num = num * 10 + sign * digit;
		i++;
	}

	if (idx) { *idx = i; }
	return num;
}

std::string to_string(int num) {
	std::ostringstream oss;
	oss << num;
	return oss.str();
}

std::string to_string(long num) {
	std::ostringstream oss;
	oss << num;
	return oss.str();
}

double str_to_double(const std::string &num_str)
{
	std::istringstream iss(num_str);
	double result;

	iss >> result;
	return result;
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

std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (HttpMessageParser::is_whitespace(field_value_with_ows[before_pos]) == true && before_pos != field_value_with_ows.length())
		before_pos++;
	while (HttpMessageParser::is_whitespace(field_value_with_ows[after_pos]) == true && after_pos != 0)
		after_pos--;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
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

std::string	skip_lastsemicolon(const std::string &word) {
	return word.substr(0, word.find(';'));
}

std::string obtain_unquote_str(const std::string &quoted_str) {
	return quoted_str.substr(1, quoted_str.length() - 2);
}

std::string to_lower(const std::string &str) {
	std::string lower_str;
	char c;

	for (std::size_t pos = 0; pos < str.length(); ++pos) {
		c = static_cast<char>(
				std::tolower(static_cast<unsigned char>(str[pos])));
		lower_str += c;
	}
	return lower_str;
}

Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t pos,
												char tail_delimiter,
												std::size_t *end_pos) {
	std::size_t delim_pos, len;
	std::string	ret_str;

	if (tail_delimiter == '\0') {
		ret_str = src_str.substr(pos);
		if (end_pos) { *end_pos = src_str.length(); }
		return Result<std::string, int>::ok(ret_str);
	}

	delim_pos = src_str.find(tail_delimiter, pos);
	if (delim_pos == std::string::npos) {
		return Result<std::string, int>::err(ERR);
	}
	len = delim_pos - pos;

	ret_str = src_str.substr(pos, len);
	if (end_pos) { *end_pos = pos + len; }
	return Result<std::string, int>::ok(ret_str);
}

}  // namespace StringHandler
