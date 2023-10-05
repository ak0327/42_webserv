#ifndef SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
#define SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_

#include <string>
#include "../../HandlingString/HandlingString.hpp"

class ConfigHandlingString
{
	private:
		ConfigHandlingString();
		~ConfigHandlingString();
	public:
		static	bool		is_nomeanig_line(const std::string &line);
		static	std::string	get_value_without_lastsemicolon(const std::string &value);
};

#endif  // SRCS_CONFIG_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRING_HPP_
