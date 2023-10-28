#ifndef SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
#define SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_

#include <string>
#include "../../HandlingString/HandlingString.hpp"
#include "../NumericHandle/NumericHandle.hpp"

#define	IS_OK_FIELD_HEADER 0
#define	IS_OK_FIELD_VALUE 0
#define	NO_FIELD_HEADER 1
#define NO_FIELD_VALUE 2
#define NO_LAST_SEMICOLON 3
#define NO_SEMICOLON 4
#define MULTIPLE_SEMICOLON 5
#define IS_NOT_FIELD_VALUE_FORMAT 6


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
		static	int	is_field_header(const std::string &config_line, size_t *pos);
		static	int	is_field_value(const std::string &config_line, size_t *pos);
		static	bool	show_error_message(const std::string	&config_line, const int	&error_type);
		static	bool	ready_boolean_field_value(const std::string &field_value);
		static	int ready_int_field_value(const std::string &field_value);
		static	size_t	ready_size_t_field_value(const std::string &field_value);
		static	std::string	ready_string_field_value(const std::string &field_value);
		static	std::vector<std::string>	ready_string_vector_field_value(const std::string &field_value);
};

#endif  // SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
