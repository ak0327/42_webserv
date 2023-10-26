#ifndef SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
#define SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_

#include <string>
#include <vector>
#include "../LocationConfig/LocationConfig.hpp"
#include "../ServerConfig/ServerConfig.hpp"
#include "../../HandlingString/HandlingString.hpp"
#include "../ConfigHandlingString/ConfigHandlingString.hpp"

#define	IS_OK 0
#define	IS_NOT_ENDWORD_EXIST 6
#define	IS_NOT_START_BLOCK 7
#define	IS_NOT_EXIST_KEYWORD_SERVER 8
#define	IS_NOT_EXIST_KEYWORD_LOCATION 9
#define IS_NOT_ENDWORD_CURLY_BRACES 10
#define	IS_SERVER_BLOCK_KEY_ALREADY_EXIST 11
#define	IS_LOCATION_BLOCK_KEY_ALREADY_EXIST 12
#define	IS_NOT_FIELD_KEY_PRINTABLE 13
#define	IS_NOT_CURLY_BRACES_EXIST 14
#define	IS_NOT_ONLY_CURLY_BRACES 15
#define	IS_NOT_LAST_WARD_SEMICOLON 16

class IsConfigFormat
{
	private:
		IsConfigFormat();
		IsConfigFormat(const IsConfigFormat &other);
		IsConfigFormat& operator=(const IsConfigFormat &other);
		~IsConfigFormat();
	public:
		static	int	is_start_location_block(const std::string	&config_line, \
													std::string *config_location_path);
		static	int	is_start_location_block(const std::string &config_line);
		static	int	is_start_server_block(const std::string	&config_line, \
													bool	*in_server_block);
		static	int	is_location_block_format(const std::string &config_line);
		static	int	do_input_field_key_field_value(const std::string	&config_line, \
														LocationConfig	*server_config, \
											std::vector<std::string>	*field_header_vector);
		static	int	is_server_block_format(const std::string	&config_line, \
									std::vector<std::string>	field_headers);
		static	int	do_input_field_key_field_value(const std::string	&config_line, \
														ServerConfig	*server_config, \
											std::vector<std::string>	*field_header_vector);
};

#endif  // SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
