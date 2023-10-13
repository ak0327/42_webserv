#include "Config.hpp"

// ready_系の関数では格納を行なっているが
// ready系の関数が二つあるのはtestconfig2のようなserverblockの要素が
// 後に存在してしまう可能性があるため
// serverblockの情報の取得→locationblockの情報を取得
// 上記の流れを行いたい場合どうしても二回開く必要がある（要相談

void	Config::set_serverconfig_ready_next_serverconfig(AllConfig *Configs, ServerConfig *serverconfig, \
std::vector<std::string> *fieldkey_map, std::vector<std::vector<std::string> > *servername_list)
{
	Configs->set_host_config(*serverconfig);
	servername_list->push_back(serverconfig->get_server_name());
	this->_all_configs[serverconfig->get_server_name()] = *Configs;
	Configs->clear_information();
	serverconfig->clear_serverconfig();
	fieldkey_map->clear();
}

bool	Config::ready_server_config_format(const std::string &config_file_name, \
std::vector<std::vector<std::string> > *servername_list)
{
	AllConfig					Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool						in_server_block = false;
	bool						in_location_block = false;
	ServerConfig				serverconfig;
	std::ifstream				config_lines(config_file_name.c_str());
	std::string					config_line;
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
			else if (ConfigHandlingString::is_block_end(config_line))
				set_serverconfig_ready_next_serverconfig(&Configs, &serverconfig, &fieldkey_map, servername_list);
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::is_locationblock_config(config_line, &in_location_block))
			continue;
		else  // 上記3つ以外の場合、状況としてはありえないためfalseになる
			return this->report_errorline(config_line);
	}
	return (true);
}

void	Config::ready_next_locationconfig(LocationConfig *locationconfig, const std::vector<std::string> &server_name, bool *in_server_block)
{
	locationconfig->clear_location_keyword();
	locationconfig->set_serverblock_infs(this->get_same_allconfig(server_name).get_host_config());
	*in_server_block = true;
}

bool	Config::ready_location_config(const std::string &config_file_name, \
std::vector<std::vector<std::string> >::iterator servername_itr)
{
	std::vector<std::string>							location_fieldkey_map;
	std::ifstream										config_lines(config_file_name.c_str());
	std::string											config_line;
	std::string											location_path;
	LocationConfig										locationconfig;
	bool												in_server_block = false;
	bool												in_location_block = false;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_nomeanig_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_serverblock(config_line))
			ready_next_locationconfig(&locationconfig, *servername_itr, &in_server_block);
		else if (in_server_block == true && in_location_block == false)
		{
			if (IsConfigFormat::is_start_locationblock(config_line))
				in_location_block = true;
			else if (ConfigHandlingString::is_block_end(config_line))
				servername_itr++;
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::ready_locationblock_config(config_line, &in_location_block, &locationconfig, &location_fieldkey_map))
		{
			if (ConfigHandlingString::is_block_end(config_line))
			{
				this->_all_configs[*servername_itr].set_location_config(location_path, locationconfig);
				location_fieldkey_map.clear();
				locationconfig.clear_location_keyword();
				locationconfig.set_serverblock_infs(this->get_same_allconfig(*servername_itr).get_host_config());
			}
		}
		else
			return this->report_errorline(config_line);
	}
	return (true);
}

Config::Config(const std::string &config_file_name): _is_config_format(true)
{
	std::ifstream													test_open(config_file_name.c_str());
	std::vector<std::vector<std::string> >							servername_list;

	if (!(test_open.is_open() && this->ready_server_config_format(config_file_name, &servername_list)))
	{
		this->_is_config_format = false;
		return;
	}
	if (!(ready_location_config(config_file_name, servername_list.begin())))
	{
		this->_is_config_format = false;
		return;
	}
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

bool Config::report_errorline(const std::string &line)
{
	std::cerr << "FORMAT ERROR OCURED" << std::endl;
	std::cerr << "|====== TARGET LINE ======|" << std::endl;
	std::cerr << "|" << line << std::endl;
	std::cerr << "|=========================|" << std::endl;
	return (false);
}
