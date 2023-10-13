#ifndef SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
#define SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_

# include <ctype.h>
# include <cctype>
# include <climits>
# include <algorithm>
# include <fstream>
# include <iostream>
# include <limits>
# include <sstream>
# include <string>
# include <vector>

class HandlingString
{
	private:
		HandlingString();
		~HandlingString();
	public:
		static	bool						is_endl_semicolon_and_no_inner_semicoron(const std::string &word);
		static	bool						is_ows(const char &c);
		static	bool						is_printable_content(const std::string &value);
		static	std::string					obtain_unquote_str(const std::string &quoted_str);
		static	std::string					obtain_without_ows_value(const std::string &field_value_with_ows);
		static	std::string					skip_lastsemicolon(const std::string &word);
		static	void						skip_ows(const std::string &line, size_t *pos);
		static	void						skip_no_ows(const std::string &line, size_t *pos);
		static	bool						is_field_value(const std::string &line, size_t *pos);
};

#endif  // SRCS_HANDLINGSTRING_HANDLINGSTRING_HPP_
