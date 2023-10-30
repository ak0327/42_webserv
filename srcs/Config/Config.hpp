#pragma once

# include <fstream>
# include <map>
# include <set>
# include <sstream>
# include <string>
# include <vector>
# include "AllConfig.hpp"
# include "ConfigHandlingString.hpp"
# include "HandlingString.hpp"
# include "IsConfigFormat.hpp"
# include "ServerConfig.hpp"

enum config_result {
	OK = 0,
	IS_OK_START_SERVER_BLOCK = 0,
	IS_OK_START_LOCATION_BLOCK = 0,
	IS_OK_BLOCK_END = 0,
	IS_OK_IN_SERVER_BLOCK = 0,
	CONFIG_FORMAT_OK = 0,
	FIELD_HEADER_OK = 0,
	FIELD_VALUE_OK = 0,

	IS_NOT_SERVER_CONFIG_FORMAT,
	IS_NOT_LOCATION_CONFIG_FORMAT,
	IS_ALREADY_EXIST_FIELD_KEY,
	NOT_ALLOWED_SERVER_BLOCK_FORMAT,
	NOT_ALLOWED_CONFIG_FORMAT,
	NOT_END_CONFIG,

	NOT_ENDWORD_EXIST,
	NOT_START_BLOCK,
	NOT_EXIST_KEYWORD_SERVER,
	NOT_EXIST_KEYWORD_LOCATION,
	NOT_ENDWORD_CURLY_BRACES,
	SERVER_BLOCK_KEY_ALREADY_EXIST,
	LOCATION_BLOCK_KEY_ALREADY_EXIST,
	NOT_FIELD_KEY_PRINTABLE,
	NOT_CURLY_BRACES_EXIST,
	NOT_ONLY_CURLY_BRACES,
	NOT_LAST_WARD_SEMICOLON,
	TOO_MANY_CURLY_BRACES,
	NOT_PRINTABLE,
	NOT_START_CURLY_BRACES,
	FORBIDDEN_WORD,

	NO_FIELD_HEADER,
	NO_FIELD_VALUE,
	NO_LAST_SEMICOLON,
	NO_SEMICOLON,
	MULTIPLE_SEMICOLON,
	NOT_FIELD_VALUE_FORMAT
};

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

class Config
{
	private:
		bool _is_config_format;
		std::map<std::vector<std::string>, AllConfig> _all_configs;

		bool report_errorline(const std::string &config_line,
							  const size_t &line,
							  const int &error_type);
		bool ready_location_config(const std::string &config_file_name,
								   std::vector<std::vector<std::string> >::iterator server_name_itr);
		void init_location_config_with_server_config(LocationConfig	*location_config,
													 const std::vector<std::string>	&server_name,
													 bool *in_server_block);
		bool ready_server_config(const std::string	&config_file_name,
								 std::vector<std::vector<std::string> >	*server_name_list);
		int server_block_action(const std::string &config_line,
								bool *in_server_block,
								bool *in_location_block,
								AllConfig *configs,
								ServerConfig *server_config,
								std::vector<std::string> *field_headers,
								std::vector<std::vector<std::string> > *server_name_list);
		void set_server_config_to_allconfigs(AllConfig *configs,
											 ServerConfig *server_config,
											 std::vector<std::vector<std::string> > *server_name_list);
		void init_server_config_and_allconfigs_and_field_header_map(AllConfig *configs,
																	ServerConfig *server_config,
																	std::vector<std::string> *field_header_map);
		AllConfig get_same_allconfig(const std::vector<std::string> &server_name);

	public:
		explicit Config(const std::string &config_file_name);
		~Config();

		bool get_is_config_format();
		std::map<std::vector<std::string>, AllConfig>	get_all_configs();
		AllConfig	get_same_allconfig(const std::string &server_name);
};
