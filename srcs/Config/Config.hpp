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

#define IS_OK 0
#define	IS_OK_START_SERVER_BLOCK 0
#define	IS_OK_BLOCK_END 0
#define	IS_OK_IN_SERVER_BLOCK 0
#define	IS_NOT_SERVER_CONFIG_FORMAT 1
#define	IS_NOT_LOCATION_CONFIG_FORMAT 2
#define	IS_ALREADY_EXIST_FIELD_KEY 3
#define	NOT_ALLOWED_SERVER_BLOCK_FORMAT 4
#define NOT_ALLOWED_CONFIG_FORMAT 5
#define	NOT_END_CONFIG 6

// 以下のような配置構成にする必要がある　命名は最適解分からず
// 何かしらのクラス -> AllConfigと仮称
// | ---- servernameなし　-> server_config
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
		bool	report_errorline(const std::string &config_line, const size_t &line);
		bool	ready_location_config(const std::string	&config_file_name, \
	std::vector<std::vector<std::string> >::iterator	server_name_itr);
		void	init_location_config_with_server_config(LocationConfig	*location_config, \
										const std::vector<std::string>	&server_name, \
																bool	*in_server_block);
		bool	ready_server_config(const std::string	&config_file_name, \
				std::vector<std::vector<std::string> >	*server_name_list);
		int	server_block_action(const std::string	&config_line, \
											bool	*in_server_block, \
											bool	*in_location_block, \
										AllConfig	*Configs, \
									ServerConfig	*server_config, \
						std::vector<std::string>	*field_headers, \
			std::vector<std::vector<std::string> >	*server_name_list);
		void	set_server_config_to_allconfigs(AllConfig	*Configs, \
											ServerConfig	*server_config, \
					std::vector<std::vector<std::string> >	*server_name_list);
		void	init_server_config_and_allconfigs(AllConfig	*Configs, \
											ServerConfig	*server_config, \
								std::vector<std::string>	*field_header_map);
	public:
		explicit Config(const std::string &config_file_name);
		~Config();
		bool	get_is_config_format(void){ return this->_is_config_format; }
		std::map<std::vector<std::string>, AllConfig>	get_all_configs(void);
		AllConfig	get_same_allconfig(const std::string &server_name);
		AllConfig	get_same_allconfig(const std::vector<std::string> &server_name);
};

#endif  // SRCS_CONFIG_CONFIG_HPP_
