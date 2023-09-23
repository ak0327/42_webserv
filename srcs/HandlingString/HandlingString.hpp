#ifndef SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
#define SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_

#include <ctype.h>
#include <cctype>
#include <climits>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

class HandlingString
{
	private:
		HandlingString();
		~HandlingString();
	public:
		static	bool						compare_word(const std::string &tgt_string,  const std::string &key);
		static	bool						is_double_or_not(const std::string &value);
		static	bool						is_doublequote_format(const std::string &value);
		static	bool						is_lastword_semicolon(const std::string &word);
		static	bool						is_ows(const char &c);
		static	bool						is_positive_int_or_not(const std::string &value);
		static	bool						is_printablecontent(const std::string &value);
		static	bool						is_positive_and_under_intmax(const std::string &word);
		static	double						str_to_double(const std::string &num_str);
		static	int							str_to_int(const std::string &word);
		static	int							to_digit(const char &c);
		static	std::vector<std::string> 	input_arg_to_vector_without_firstword(const std::string &words);
		static	std::string					int_to_str(int num);
		static	std::string					obtain_word_after_delimiter(const std::string &str, char delimiter);
		static	std::string					obtain_unquote_str(const std::string &quoted_str);
		static	std::string					obtain_withoutows_value(const std::string &field_value_with_ows);
		static	std::string					obtain_weight(const std::string &other);
		static	std::string					obtain_word_before_delimiter(const std::string &other, const char &delimiter);
		static	std::string					skip_lastsemicolon(const std::string &word);
};

#endif  // SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
