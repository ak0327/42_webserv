#include "HandlingString.hpp"

bool	HandlingString::is_end_with_cr(const std::string &value)
{
	if (value.length() <= 1)
		return (false);
	return (value[value.length() - 1] == '\r');
}

bool	HandlingString::is_double(const std::string &value)
{
	size_t	dot_counter = 0;
	size_t	now_pos = 0;
	size_t	value_length = value.length();
	std::istringstream ss(value);
	double value_to_double;

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
	return (true);
}

size_t count_char(const std::string &str, const char c)
{
	std::size_t	count = 0;
	std::size_t pos = 0;

	while (str[pos]) {
		count += (str[pos] == c) ? 1 : 0;
		pos++;
	}
	return count;
}

bool HandlingString::is_doublequote_format(const std::string &value) {
	std::size_t head, tail;

	if (count_char(value, '"') != 2) {
		return false;
	}
	head = value.find('"');
	tail = value.rfind('"');
	return head == 0 && tail + 1 == value.length();
}

bool	HandlingString::is_lastword_semicolon(const std::string &word)
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

bool HandlingString::is_ows(const char &c)
{
	return c == ' ' || c == '\t';
}

bool	HandlingString::is_printable_content(const std::string &value)
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

bool	HandlingString::is_positive_and_under_intmax(const std::string &num_str)
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

std::vector<std::string> HandlingString::input_arg_to_vector_without_firstword(const std::string &words)
{
	std::string					replaced_words = HandlingString::skip_lastsemicolon(words);
	std::string					word;
	std::istringstream			splited_words(replaced_words);
	std::vector<std::string>	ans;

	splited_words >> word;
	while (splited_words >> word)
		ans.push_back(word);
	return (ans);
}

double HandlingString::str_to_double(const std::string &num_str)
{
	std::istringstream iss(num_str);
    double result;
    iss >> result;
    return result;
}

int HandlingString::to_digit(const char &c)
{
	return (c - '0');
}

int	HandlingString::str_to_int(const std::string &word)
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

std::string	HandlingString::skip_lastsemicolon(const std::string &word)
{
	return word.substr(0, word.find(';'));
}

std::string HandlingString::int_to_str(int num)
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

std::string HandlingString::obtain_word_before_delimiter(const std::string &field_value, const char &delimiter)
{
	return field_value.substr(0, field_value.find(delimiter));
}

std::string HandlingString::obtain_word_after_delimiter(const std::string &str, char delimiter)
{
	return str.substr(str.find(delimiter) + 1);
}

std::string	HandlingString::obtain_weight(const std::string &field_value)
{
	return (HandlingString::obtain_word_after_delimiter(field_value, '='));
}

std::string HandlingString::obtain_unquote_str(const std::string &quoted_str)
{
	return quoted_str.substr(1, quoted_str.length() - 2);
}

std::string HandlingString::obtain_withoutows_value(const std::string &field_value_with_ows)
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
