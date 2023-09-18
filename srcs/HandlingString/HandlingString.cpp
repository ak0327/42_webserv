#include "HandlingString.hpp"

std::vector<std::string> HandlingString::inputarg_tomap_without_firstword(std::string const &words)
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

bool HandlingString::return_matchpattern(std::string true_word, std::string false_word, std::string tgt_word)
{
	if (true_word == tgt_word)
		return (true);
	else if (false_word == tgt_word)
		return (false);
	return (false);
}

std::string	HandlingString::skipping_first_emptyword(std::string const &word)
{
	std::string	tmp_word;
	size_t		word_length = word.length();
	size_t		word_nowposl = 0;

	while (word[word_nowposl] == ' ' || word[word_nowposl] == '\t')
		word_nowposl++;
	while (word_nowposl != word_length)
	{
		tmp_word = tmp_word + word[word_nowposl];
		word_nowposl++;
	}
	return (tmp_word);
}

std::string HandlingString::skipping_emptyword(std::string const &word)
{
	std::istringstream	splited_words(word);
	std::string			src;
	std::string			all_src;

	while (splited_words >> src)
		all_src = all_src + src;
	return (all_src);
}

bool	HandlingString::check_under_intmax(std::string const &word)
{
	size_t	pos = 0;
	size_t	sum = 0;

	while (word[pos] != '\0')
	{
		if (std::isdigit(word[pos]) == false && word[pos] != ';')
			return (false);
		pos++;
	}
	if (pos > 12)  // INT_MAXの桁数を明らかに超えるなら計算の必要はない
		return (false);
	pos = 0;
	while (word[pos] != '\0')
	{
		sum = sum * 10 + (word[pos] - '0');
		if (sum >= INT_MAX)
			return (false);
		pos++;
	}
	return (true);
}

int	HandlingString::str_to_int(std::string const &word)
{
	size_t	pos = 0;
	size_t	sum = 0;

	pos = 0;
	while (word[pos] != '\0')
	{
		sum = sum * 10 + (word[pos] - '0');
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
	size_t		index = word.find(';');

	if (index == std::string::npos)
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

bool	HandlingString::compare_word(std::string const &tgt_string, std::string const &key)
{
	if (key == tgt_string)
		return (true);
	return (false);
}

std::string HandlingString::obtain_second_word(std::string const &line)
{
	std::istringstream	splited_woeds(line);
	std::string			f_word;
	std::string			s_word;
	std::string			t_word;

	splited_woeds >> f_word >> s_word >> t_word;
	return (s_word);
}

std::string HandlingString::int_to_str(size_t pos)
{
	std::string result;

    if (pos == 0)
	{
        result = "0";
		return result;
	}
	while (pos > 0)
	{
		result =  static_cast<char>('0' + pos % 10) + result;
		pos /= 10;
	}
    return result;
}

void HandlingString::show_vector_contents(std::vector<std::string> subject)
{
	if (subject.empty() == true)
	{
		std::cout << " * NO CONTENTS INSERTED * ";
		return;
	}
	std::vector<std::string>::iterator it = subject.begin();
	if (it == subject.end())
		std::cout << *it << std::endl;
	while (it != subject.end())
	{
		std::cout << *it << " ";
		it++;
	}
}

void HandlingString::ft_strcpy(char *input_memory, std::string const &sub)
{
	size_t	error_message_len = 0;
	while (error_message_len != sub.length())
	{
		input_memory[error_message_len] = sub[error_message_len];
		error_message_len++;
	}
	input_memory[error_message_len] = '\0';
}

std::string HandlingString::obtain_beforeword(const std::string other, char delimiter)
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

bool	HandlingString::check_int_or_not(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	now_location = 0;

	while (now_location != value_length)
	{
		if (!('0' <= value[now_location] && value[now_location] <= '9'))
			return (false);
		now_location++;
	}
	return (true);
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

std::string HandlingString::obtain_value(const std::string &value)
{
	size_t		before_location = 0;
	size_t		after_location = value.length() - 1;
	while (value[before_location] == ' ' || value[before_location] == '\t')
		before_location++;
	while (value[after_location] == ' ' || value[after_location] == '\t')
		after_location--;
	return (value.substr(before_location, after_location - before_location + 1));
}

bool	HandlingString::check_printablecontent(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	now_location = 0;
	while (now_location != value_length)
	{
		if (0<= static_cast<int>(value[now_location]) && static_cast<int>(value[now_location]) <= 31)
			return (false);
		now_location++;
	}
	return (true);
}
