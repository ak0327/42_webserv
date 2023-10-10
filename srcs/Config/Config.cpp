#include "Config.hpp"

// ready_系の関数では格納を行なっているが
// ready系の関数が二つあるのはtestconfig2のようなserverblockの要素が
// 後に存在してしまう可能性があるため
// serverblockの情報の取得→locationblockの情報を取得
// 上記の流れを行いたい場合どうしても二回開く必要がある（要相談

bool	Config::ready_server_config_format(const std::string &config_file_name, std::vector<std::vector<std::string> > *servername_list, \
std::map<std::vector<std::string>, std::vector<std::string> > *server_fieldkey_maps)
{
	std::ifstream				config_lines(config_file_name.c_str());
	std::string					config_line;
	ServerConfig				serverconfig;
	AllConfig					Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool						in_server_block = false;
	bool						in_location_block = false;
	std::string					location_path;
	std::vector<std::string>	fieldkey_map;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_nomeanig_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_serverblock(config_line))
			in_server_block = true;
		else if (in_server_block == true && in_location_block == false && \
		IsConfigFormat::ready_serverblock_format(config_line, &in_server_block, &serverconfig, &fieldkey_map))
		{
			if (IsConfigFormat::is_start_locationblock(config_line))
				in_location_block = true;
			else if (HandlingString::obtain_without_ows_value(config_line) == "}")
			{
				(*server_fieldkey_maps)[serverconfig.get_server_name()] = fieldkey_map;
				Configs.set_host_config(serverconfig);
				servername_list->push_back(serverconfig.get_server_name());
				this->_all_configs[serverconfig.get_server_name()] = Configs;
				Configs.clear_information();
				serverconfig.clear_serverconfig();
				fieldkey_map.clear();
			}
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::is_locationblock_config(config_line, &in_location_block))
			continue;
		else  // 上記3つ以外の場合、状況としてはありえないためfalseになる
		{
			std::cout << "Server Config Error config line is -> |" << config_line << "|" << std::endl;
			return (false);
		}
	}
	return (true);
}

void	Config::ready_location_config(const std::string &config_file_name, std::vector<std::vector<std::string> > servername_list)
{
	std::vector<std::vector<std::string> >::iterator	servername_itr = servername_list.begin();
	std::ifstream										config_lines(config_file_name.c_str());  // 変更が反映されない
	std::string											config_line;
	std::string											location_path;
	LocationConfig										locationconfig;
	AllConfig											Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool												in_server_block = false;
	bool												in_location_block = false;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_nomeanig_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_serverblock(config_line))
		{
			locationconfig.clear_location_keyword();
			locationconfig.set_serverblock_infs(this->get_same_allconfig(*servername_itr).get_host_config());
			in_server_block = true;
		}
		else if (in_server_block == true && in_location_block == false)
		{
			if (IsConfigFormat::is_start_locationblock(config_line))
				in_location_block = true;
			else if (HandlingString::obtain_without_ows_value(config_line) == "}")
				servername_itr++;
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::ready_locationblock_config(config_line, &in_location_block, &locationconfig))
		{
			if (HandlingString::obtain_without_ows_value(config_line) == "}")
			{
				this->_all_configs[*servername_itr].set_location_config(location_path, locationconfig);
				locationconfig.clear_location_keyword();
				locationconfig.set_serverblock_infs(this->get_same_allconfig(*servername_itr).get_host_config());
			}
		}
	}
}

Config::Config(const std::string &config_file_name): _is_config_format(true)
{
	std::ifstream										test_open(config_file_name.c_str());
	std::vector<std::vector<std::string> >				servername_list;
	std::map<std::vector<std::string>, std::vector<std::string> >	server_fieldkey_map;

	if (!(test_open.is_open() && this->ready_server_config_format(config_file_name, &servername_list, &server_fieldkey_map)))
	{
		this->_is_config_format = false;
		return;
	}
	ready_location_config(config_file_name, servername_list);
}

Config::~Config(){}

std::map<std::vector<std::string>, AllConfig>	Config::get_all_configs()
{
	return (this->_all_configs);
}

AllConfig Config::get_same_allconfig(const std::vector<std::string> servername)
{
	return (this->_all_configs[servername]);
}
