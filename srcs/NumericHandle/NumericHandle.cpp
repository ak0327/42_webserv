#include "NumericHandle.hpp"

bool	NumericHandle::is_positive_under_intmax_double(const std::string &value)
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

bool	NumericHandle::is_positive_and_under_intmax_int(const std::string &num_str)
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

double NumericHandle::str_to_double(const std::string &num_str)
{
	std::istringstream iss(num_str);
    double result;

    iss >> result;
    return result;
}

int	NumericHandle::str_to_int(const std::string &word)
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

int NumericHandle::to_digit(const char &c)
{
	return (c - '0');
}

std::string NumericHandle::int_to_str(int num)
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
