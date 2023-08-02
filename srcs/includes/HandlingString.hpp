/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   HandlingString.hpp                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user <user@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/29 19:48:07 by user              #+#    #+#             */
/*   Updated: 2023/08/02 22:40:49 by user             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef HandlingString_HPP
#define HandlingString_HPP

#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>

class HandlingString
{
	private:
		// うえ〜〜い

	public:
		static	bool						check_lastword_semicoron(std::string const &word);
		static	bool						compare_word(std::string const &tgt_string, std::string const &key);
		static	std::string					skip_lastsemicoron(std::string const &word);
		static	std::vector<std::string> 	inputarg_tomap_without_firstword(std::string const &words);
		static	bool						return_matchpattern(std::string True_wd, std::string False_wd, std::string sub_wd);
		static	std::string					skipping_emptyword(std::string const &word);
		static	bool						check_under_intmax(std::string const &word);
		static	int							str_to_int(std::string const &word);
		static	void						error_show(std::string const &word, size_t const &pos);
		static	std::string					obtain_second_word(std::string const &line);//空白文字を分割して二番目を格納する
};

#endif