#ifndef SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
#define SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_

#include <string>
#include "../../HandlingString/HandlingString.hpp"
#include "../ServerConfig/ServerConfig.hpp"
#include "../LocationConfig/LocationConfig.hpp"

class IsConfigFormat
{
	private:
		IsConfigFormat();
		IsConfigFormat(const IsConfigFormat &other);
		IsConfigFormat& operator=(const IsConfigFormat &other);
		~IsConfigFormat();
	public:
		static	bool	is_start_locationblock(const std::string &line, std::string *config_location_path);
		static	bool	is_start_serverblock(const std::string &line);
		static	bool	is_locationblock_format(const std::string &line, bool *in_location_block, LocationConfig *locationconfig);
		static	bool	is_serverblock_format(const std::string &line, \
		bool *in_server_block, bool *in_location_block, ServerConfig *serverinfs, std::string *location_path);
};

#endif  // SRCS_CONFIG_ISCONFIGFORMAT_ISCONFIGFORMAT_HPP_
