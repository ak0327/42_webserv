#ifndef SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
#define SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_

#include <string>
#include <vector>
#include "../LocationConfig/LocationConfig.hpp"
#include "../ServerConfig/ServerConfig.hpp"
#include "../../HandlingString/HandlingString.hpp"
#include "../ConfigHandlingString/ConfigHandlingString.hpp"

#define	IS_OK 0
#define	IS_NOT_ENDWORD_EXIST 7
#define	IS_NOT_START_BLOCK 8
#define	IS_NOT_EXIST_KEYWORD_SERVER 9
#define	IS_NOT_EXIST_KEYWORD_LOCATION 10
#define IS_NOT_ENDWORD_CURLY_BRACES 11
#define	IS_SERVER_BLOCK_KEY_ALREADY_EXIST 12
#define	IS_LOCATION_BLOCK_KEY_ALREADY_EXIST 13
#define	IS_NOT_FIELD_KEY_PRINTABLE 14
#define	IS_NOT_CURLY_BRACES_EXIST 15
#define	IS_NOT_ONLY_CURLY_BRACES 16
#define	IS_NOT_LAST_WARD_SEMICOLON 17
#define IS_TOO_MANY_CURLY_BRACES 18
#define IS_NOT_PRINTABLE 19
#define IS_NOT_START_CURLY_BRACES 26
#define IS_FORBIDDEN_WORD 27

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
		static	int	input_field_key_field_value(const std::string	&config_line, \
														LocationConfig	*server_config);
		static	int	is_server_block_format(const std::string	&config_line, \
									std::vector<std::string>	field_headers);
		static	int	input_field_key_field_value(const std::string	&config_line, \
														ServerConfig	*server_config, \
											std::vector<std::string>	*field_header_vector);
};

#endif  // SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
