#ifndef	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
#define	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_

#include <map>
#include <string>
#include "../ServerConfig/ServerConfig.hpp"
#include "../LocationConfig/LocationConfig.hpp"


class	AllConfig
{
	private:
		ServerConfig							_host_config;
		// host名が存在しないと、テンプレートのhostみたいに扱われる port番号が左の値になる
		// portは一つ確定なので特段mapで持つ必要はない
		std::map<std::string, LocationConfig>	_location_config;
	public:
		AllConfig(const ServerConfig &host_configs, const std::map<std::string, LocationConfig> &_location_config);
		AllConfig();
		~AllConfig();
		void									set_host_config(const ServerConfig &host_config);
		void									set_location_config(const std::string &location_path, const LocationConfig &location_config);
		void									clear_information();
		ServerConfig							get_host_config(void);
		LocationConfig							get_location_host_config(const std::string &location_name);
};

#endif  // SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
