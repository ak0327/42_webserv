#ifndef	AllConfig_HPP_
#define	AllConfig_HPP_

#include "../ServerConfig/ServerConfig.hpp"
#include "../LocationConfig/LocationConfig.hpp"

class	AllConfig
{
	private:
		ServerConfig							_host_config; // host名が存在しないと、テンプレートのhostみたいに扱われる port番号が左の値になる // portは一つ確定なので特段mapで持つ必要はない
		std::map<std::string, LocationConfig>	_location_config;
	public:
		AllConfig(ServerConfig &host_configs, std::map<std::string, LocationConfig> &_location_config);
		AllConfig();
		~AllConfig();
		void									set_host_config(const ServerConfig &host_config);
		void									set_location_config(const std::string &location_path, LocationConfig &location_config);
		void									clear_information();
		ServerConfig							get_host_config(void);
		LocationConfig							get_location_host_config(const std::string &location_name);
};

#endif
