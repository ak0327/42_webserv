#ifndef SRCS_HANDLINGSTRING_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRINGHPP_
#define SRCS_HANDLINGSTRING_CONFIGHANDLINGSTRING_CONFIGHANDLINGSTRINGHPP_

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

#endif
