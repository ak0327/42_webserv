/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   HandlingString.cpp                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user <user@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/29 19:47:10 by user              #+#    #+#             */
/*   Updated: 2023/07/29 20:06:36 by user             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/HandlingString.hpp"

std::vector<std::string> HandlingString::inputargtomap_withoutfirst(std::string const &words)
{
	std::string					replaced_words = HandlingString::skip_lastsemicoron(words);
	std::string					word;
	std::istringstream			splited_words(replaced_words);
	std::vector<std::string>	ans;

	splited_words >> word;
	while (splited_words >> word)
		ans.push_back(word);
	return (ans);
}

bool HandlingString::return_matchpattern(std::string True_wd, std::string False_wd, std::string sub_wd)
{
	if (True_wd == sub_wd)
		return (true);
	else if (False_wd == sub_wd)
		return (false);
	return (false);
}

std::string HandlingString::skipping_emptywd(std::string const &word)
{
	std::istringstream	splited_words(word);
	std::string			src;
	std::string			all_src;

	while (splited_words >> src)
		all_src = all_src + src;
	return (all_src);
}

bool	HandlingString::ch_under_intmax(std::string const &word)
{
	size_t	pos = 0;
	size_t	sum = 0;

	while (word[pos] != '\0')
	{
		if (!('0' <= word[pos] && word[pos] <= '9') && word[pos] != ';')
			return (false);
		pos++;
	}
	if (pos > 12)//INT_MAXの桁数を明らかに超えるなら計算の必要はない
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

bool	HandlingString::ch_lastword_semicoron(std::string const &word)
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