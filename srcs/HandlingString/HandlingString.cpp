#include "HandlingString.hpp"

std::vector<std::string> HandlingString::inputarg_to_vector_without_firstword(std::string const &words)
{
	std::string					replaced_words = HandlingString::skip_lastsemicoron(words);
	std::string					word;
	std::istringstream			splited_words(replaced_words);
	std::vector<std::string>	ans;

	splited_words >> word;
	// std::cout << "word is -> " << word << std::endl;
	while (splited_words >> word)
	{
		// std::cout << "word is -> " << word << std::endl;
		ans.push_back(word);
	}
	return (ans);
}

bool HandlingString::return_matchpattern(std::string true_word, std::string target_word)
{
	return (true_word == target_word);
}

std::string	HandlingString::skipping_first_emptyword(std::string const &word)
{
	std::string	tmp_word;
	size_t		word_length = word.length();
	size_t		word_pos = 0;

	while (word[word_pos] == ' ' || word[word_pos] == '\t')
		word_pos++;
	while (word_pos != word_length)
	{
		tmp_word += word[word_pos];
		word_pos++;
	}
	return (tmp_word);
}

std::string HandlingString::skip_emptyword(std::string const &word)
{
	std::istringstream	splitted_words(word);
	std::string			src;
	std::string			all_src;

	while (splitted_words >> src)
		all_src += src;
	return (all_src);
}

bool	HandlingString::is_under_intmax(std::string const &word)
{
	size_t	pos = 0;

	while (word[pos] != '\0')
	{
		if (std::isdigit(word[pos]) == false && word[pos] != ';')
			return (false);
		pos++;
	}
	std::istringstream	iss(word);
	size_t				result;
	iss >> result;
	if (result > INT_MAX)
		return (false);
	return (true);
}

int HandlingString::to_digit(const char &target)
{
	return (target - '0');
}

int	HandlingString::str_to_int(std::string const &word)
{
	size_t	pos = 0;
	int		sum = 0;

	pos = 0;
	while (word[pos] != '\0')
	{
		sum = sum * 10 + to_digit(word[pos]);
		pos++;
	}
	return (sum);
}

double HandlingString::str_to_double(std::string word)
{
	std::istringstream iss(word);
    double result;
    iss >> result;
    return result;
}

bool	HandlingString::check_lastword_semicoron(std::string const &word)
{
	size_t	pos = 0;
	size_t	semicoron_count = 0;

	while (word[pos] != '\0')
	{
		if (word[pos] == ';')
			semicoron_count++;
		pos++;
	}
	if (semicoron_count != 1)
		return (false);
	if (word[pos - 1] != ';')
		return (false);
	return (true);
}

std::string	HandlingString::skip_lastsemicoron(std::string const &word)
{
	size_t		pos = 0;
	std::string	return_str;

	if (word.find(';') == std::string::npos)
		return (word);
	while (word[pos] != ';')
	{
		return_str = return_str + word[pos];
		pos++;
	}
	return (return_str);
}

void	HandlingString::error_show(std::string const &word, size_t const &pos)
{
	std::string error_one = "<< missed word! >>";
	std::string error_two = "<< missed line >>";
	std::string error_three = "===============";

	std::cout << error_three << std::endl;
	std::cout << error_one << std::endl;
	std::cout << "* " << word << std::endl;
	std::cout << error_two << std::endl;
	std::cout << "line > " << pos << std::endl;
	std::cout << error_three << std::endl;
}

std::string HandlingString::int_to_str(int num)
{
	std::string result;

    if (num == 0)
		return "0";
	while (num > 0)
	{
		result += static_cast<char>(toascii('0' + num % 10));
		num /= 10;
	}
    return result;
}

std::string HandlingString::obtain_word_beforedelimiter(const std::string &other, const char &delimiter)
{
	return other.substr(0, other.find(delimiter));
}

std::string HandlingString::obtain_afterword(const std::string other, char delimiter)
{
	return other.substr(other.find(delimiter) + 1);
}

std::string	HandlingString::obtain_weight(const std::string &other)
{
	return (HandlingString::obtain_afterword(other, '='));
}

bool	HandlingString::is_int_or_not(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	pos = 0;

	while (pos != value_length)
	{
		if (!(isdigit(value[pos])))
			return (false);
		pos++;
	}
	return (is_under_intmax(value));
}

bool	HandlingString::check_double_or_not(const std::string &value)
{
	if (value.find('.') == std::string::npos)
		return (false);
	size_t	dot_counter = 0;
	size_t	now_location = 0;
	size_t	value_length = value.length();
	while (now_location != value_length)
	{
		if (value[now_location] == '.')
		{
			dot_counter++;
			now_location++;
		}
		if (!('0' <= value[now_location] && value[now_location] <= '9'))
			return (false);
		now_location++;
	}
	if (dot_counter > 1)
		return (false);
	std::istringstream ss(value);
	double value_to_double;
	if (ss >> value_to_double)
	{
        if (value_to_double < 0)
            return (false);
        if (value_to_double <= static_cast<double>(std::numeric_limits<int>::max()))
            return (true);
        else
            return (false);
    }
	return (true);
}

bool HandlingString::check_doublequote_format(const std::string &value)
{
	size_t	now_location = 0;
	if (value[now_location] != '"')
		return (false);
	now_location++;
	while (value[now_location] != '"')
		now_location++;
	if (now_location != value.length())
		return (false);
	return (true);
}

std::string HandlingString::obtain_string_in_doublequote(const std::string &value)
{
	size_t		value_length = value.length();
	size_t		now_location = 1;
	std::string	anser;

	while (now_location != value_length - 1)
	{
		anser = anser + value[now_location];
		now_location++;
	}
	return (anser);
}

std::string HandlingString::obtain_value(const std::string &field_value)
{
	size_t		before_location = 0;
	size_t		after_location = field_value.length() - 1;
	while (is_ows(field_value[before_location]) == true)
		before_location++;
	while (is_ows(field_value[after_location]) == true)
		after_location--;
	return (field_value.substr(before_location, after_location - before_location + 1));
}

bool	HandlingString::check_printablecontent(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	now_location = 0;
	while (now_location != value_length)
	{
		if (isprint(value[now_location]) == false)
			return (false);
		now_location++;
	}
	return (true);
}

bool HandlingString::is_ows(const char &val)
{
	if (val == ' ' || val == '\t')
		return (true);
	return (false);
}
