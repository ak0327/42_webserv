#ifndef SRSC_CONFIG_CONFIG_HPP
#define SRSC_CONFIG_CONFIG_HPP

#include <fstream>
#include <sstream>
#include <string>
#include "../HandlingString/HandlingString.hpp"
#include "ConfigHandlingString/ConfigHandlingString.hpp"
#include "ConfigHandlingString/ConfigHandlingString.hpp"
#include "IsConfigFormat/IsConfigFormat.hpp"
#include "ServerConfig/ServerConfig.hpp"
#include "AllConfig/AllConfig.hpp"

#include <map>

// 以下のような配置構成にする必要がある　命名は最適解分からず
// 何かしらのクラス -> AllConfigと仮称
// | ---- servernameなし　-> host_config
// |  | ---- Server内に記載がありLocation内に記載がない　（前提のようなもの、特定のロケーションへのアクセスでない場合
// |  |      -> server_config(ServerInfsというクラス)
// |  | ---- Location内に記載があるもの （特定のロケーションへのアクセスの場合
// |  |      -> location_config(std::map<std::string, LocationConfig>という感じ、locationによって処理を分ける必要がある)
// |
// | ---- servername_a
// |  | ---- Server内に記載がありLocation内に記載がない　（前提のようなもの、特定のロケーションへのアクセスでない場合
// |  | ---- Location内に記載があるもの （特定のロケーションへのアクセスの場合
// | ---- servername_b
// |	...

class	Config
{
	private:
		bool											_is_config_format;
		std::map<std::vector<std::string>, AllConfig>	_all_configs;

	public:
		Config(const std::string &config_file_name);
		~Config();
		bool											is_config_format(const std::string &config_file_name);
		bool											get_is_config_format(void){ return this->_is_config_format; };
};

#endif
