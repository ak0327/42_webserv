#ifndef SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
#define SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_

#include <string>
#include <vector>
#include "../LocationConfig/LocationConfig.hpp"
#include "../ServerConfig/ServerConfig.hpp"
#include "../../HandlingString/HandlingString.hpp"
#include "../ConfigHandlingString/ConfigHandlingString.hpp"

class IsConfigFormat
{
	private:
		IsConfigFormat();
		IsConfigFormat(const IsConfigFormat &other);
		IsConfigFormat& operator=(const IsConfigFormat &other);
		~IsConfigFormat();
	public:
		static	bool	is_start_locationblock(const std::string &line, std::string *config_location_path);
		static	bool	is_start_locationblock(const std::string &line);
		static	bool	is_start_serverblock(const std::string &line);
		static	bool	is_locationblock_config(const std::string &line, bool *in_location_block);
		static	bool	ready_locationblock_config(const std::string &line, bool *in_location_block, \
		LocationConfig *locationconfig, std::vector<std::string> *fieldkey_map);
		static	bool	ready_serverblock_format(const std::string &line, bool *in_server_block, \
		ServerConfig *serverinfs, std::vector<std::string> *field_key_map);
};

#endif  // SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
