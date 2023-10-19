#ifndef	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
#define	SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_

#include <map>
#include <string>
#include "../LocationConfig/LocationConfig.hpp"
#include "../ServerConfig/ServerConfig.hpp"


class	AllConfig
{
	private:
		ServerConfig	_host_config;
		std::map<std::string, LocationConfig>	_location_config;
	public:
		AllConfig(const ServerConfig &host_configs, const std::map<std::string, LocationConfig> &_location_config);
		AllConfig(const AllConfig &other);
		AllConfig& operator=(const AllConfig &other);
		AllConfig();
		~AllConfig();
		void	set_host_config(const ServerConfig &host_config);
		void	set_location_config(const std::string &location_path, const LocationConfig &location_config);
		void	clear_information();
		void	clear_location_information();
		ServerConfig	get_host_config(void);
		LocationConfig	get_location_host_config(const std::string &location_name);
};

#endif  // SRCS_CONFIG_ALLCONFIG_ALLCONFIG_HPP_
