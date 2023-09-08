#ifndef HANDLINGSTRING_HPP
#define HANDLINGSTRING_HPP

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
		static	double						str_to_double(std::string word);
		static	std::string					int_to_str(size_t pos);
		static	void						error_show(std::string const &word, size_t const &pos);
		static	std::string					obtain_second_word(std::string const &line);  // 空白文字を分割して二番目を格納する
		static	void						show_vector_contents(std::vector<std::string>);
		static	void						ft_strcpy(char *input_memory, std::string const &sub);
		static	std::string					obtain_beforeword(const std::string other, char delimiter);
		static	std::string					obtain_afterword(const std::string other, char delimiter);
		static	double						obtain_weight(const std::string &other);
		static	bool						check_int_or_not(const std::string &value);
		static	bool						check_double_or_not(const std::string &value);
		static	bool						check_doublequote_format(const std::string &value);
		static	std::string					obtain_string_in_doublequote(const std::string &value);
};

#endif
