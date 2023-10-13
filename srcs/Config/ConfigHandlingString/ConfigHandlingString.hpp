#ifndef SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
#define SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_

#include <string>
#include "../../HandlingString/HandlingString.hpp"

#define	NO_FIELD_HEADER 1
#define NO_FIELD_VALUE 2
#define NO_LAST_SEMICOLON 3
#define NO_SEMICOLON 4
#define MULTIPLE_SEMICOLON 5


class ConfigHandlingString
{
	private:
		ConfigHandlingString();
		~ConfigHandlingString();
	public:
		static	bool	is_nomeanig_line(const std::string &line);
		static	bool	is_block_end(const std::string &line);
		static	bool	is_blockstart_endword(const std::string &block_endword);
		static	bool	is_field_header(const std::string &line, size_t *pos);
		static	bool	is_field_value(const std::string &line, size_t *pos);
		static	bool	ready_field_header(const std::string &line, size_t *end_pos, std::string *field_header);
		static	bool	ready_field_value(const std::string &line, size_t *end_pos, std::string *field_value);
		static	bool	show_error_message(const std::string &line, const int &error_type);
};

#endif  // SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
