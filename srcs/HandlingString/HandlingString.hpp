#ifndef SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
#define SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_

#include <ctype.h>
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <climits>
#include <limits>
#include <cctype>

class HandlingString
{
	private:
		HandlingString();
		~HandlingString();
	public:
		static	int							to_digit(const char &target);
		static	bool						check_lastword_semicoron(const std::string &word);
		static	bool						compare_word(const std::string &tgt_string,  const std::string &key);
		static	std::string					skip_lastsemicoron(const std::string &word);
		static	std::vector<std::string> 	inputarg_to_vector_without_firstword(const std::string &words);
		static	bool						return_matchpattern(std::string True_wd, std::string sub_wd);
		static	std::string					skip_emptyword(std::string const &word);
		static	std::string					skipping_first_emptyword(const std::string &word);
		static	bool						is_under_intmax(const std::string &word);
		static	int							str_to_int(const std::string &word);
		static	double						str_to_double(std::string word);
		static	std::string					int_to_str(int num);
		static	void						error_show(const std::string &word, const size_t &pos);
		static	std::string					obtain_word_beforedelimiter(const std::string &other, const char &delimiter);
		static	std::string					obtain_afterword(const std::string other, char delimiter);
		static	std::string					obtain_weight(const std::string &other);
		static	bool						is_int_or_not(const std::string &value);
		static	bool						check_double_or_not(const std::string &value);
		static	bool						check_doublequote_format(const std::string &value);
		static	std::string					obtain_string_in_doublequote(const std::string &value);
		static	std::string					obtain_value(const std::string &field_value);
		static	bool						check_printablecontent(const std::string &value);
		static	bool						is_ows(const char &val);
};

#endif  // SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
