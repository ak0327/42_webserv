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
		ConfigHandlingString(const ConfigHandlingString &other);
		ConfigHandlingString &operator=(const ConfigHandlingString &other);
	public:
		static	bool	is_ignore_line(const std::string &config_line);
		static	bool	is_block_end(const std::string &config_line);
		static	bool	is_blockstart_endword(const std::string &block_end_word);
		static	bool	is_field_header(const std::string &config_line, size_t *pos);
		static	bool	is_field_value(const std::string &config_line, size_t *pos);
		static	bool	show_error_message(const std::string	&config_line, const int	&error_type);
};

#endif  // SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
