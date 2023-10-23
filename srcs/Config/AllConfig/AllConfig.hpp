#ifndef	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
#define	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_

#include <map>
#include <string>
#include "../LocationConfig/LocationConfig.hpp"
#include "../ServerConfig/ServerConfig.hpp"


class	AllConfig
{
	private:
		ServerConfig	_server_config;
		std::map<std::string, LocationConfig>	_location_config_map;
	public:
		AllConfig(const ServerConfig &server_configs, \
					const std::map<std::string, LocationConfig> &location_config_map);
		AllConfig(const AllConfig &other);
		AllConfig& operator=(const AllConfig &other);
		AllConfig();
		~AllConfig();
		void	clear_information();
		void	clear_location_information();
		void	set_server_config(const ServerConfig &server_config);
		void	set_location_config(const std::string &location_path, \
										const LocationConfig &location_config);
		ServerConfig	get_server_config(void) const;
		LocationConfig	get_location_config(const std::string &location_path);
		std::map<std::string, LocationConfig>	get_location_config_map();
};

#endif  // SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
