#ifndef SRCS_CONFIG_CONFIG_HPP_
#define SRCS_CONFIG_CONFIG_HPP_

#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "../HandlingString/HandlingString.hpp"
#include "AllConfig/AllConfig.hpp"
#include "ConfigHandlingString/ConfigHandlingString.hpp"
#include "IsConfigFormat/IsConfigFormat.hpp"
#include "ServerConfig/ServerConfig.hpp"

// 以下のような配置構成にする必要がある　命名は最適解分からず
// 何かしらのクラス -> AllConfigと仮称
// | ---- servernameなし　-> host_config
// |  | ---- Server内に記載がありLocation内に記載がない　（前提のようなもの、特定のロケーションへのアクセスでない場合
// |  |      -> server_config(ServerInfsというクラス)
// |  | ---- Location内に記載があるもの （特定のロケーションへのアクセスの場合
// |         -> location_config(std::map<std::string, LocationConfig>という感じ、locationによって処理を分ける必要がある)
// |
// | ---- servername_a
// |  | ---- Server内に記載がありLocation内に記載がない　（前提のようなもの、特定のロケーションへのアクセスでない場合
// |  | ---- Location内に記載があるもの （特定のロケーションへのアクセスの場合
// | ---- servername_b
// |	...

class	Config
{
	private:
		bool	_is_config_format;
		std::map<std::vector<std::string>, AllConfig>	_all_configs;
		bool	report_errorline(const std::string &config_line);
		bool	ready_location_config(const std::string &config_file_name, \
										std::vector<std::vector<std::string> >::iterator server_name_itr);
		void	ready_next_locationconfig(LocationConfig *location_config, \
											const std::vector<std::string> &server_name, 
											bool *in_server_block);
		bool	ready_server_config(const std::string &config_file_name, \
											std::vector<std::vector<std::string> > *server_name_list);
		void	set_serverconfig_ready_next_serverconfig(AllConfig *Configs, \
															ServerConfig *server_config, \
															std::vector<std::string> *field_header_map, \
															std::vector<std::vector<std::string> > *server_name_list);
	public:
		explicit Config(const std::string &config_file_name);
		~Config();
		bool	get_is_config_format(void){ return this->_is_config_format; }
		std::map<std::vector<std::string>, AllConfig>	get_all_configs(void);
		AllConfig	get_same_allconfig(const std::string &server_name);
		AllConfig	get_same_allconfig(const std::vector<std::string> &server_name);
};

#endif  // SRCS_CONFIG_CONFIG_HPP_
