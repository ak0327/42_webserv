#include "Config.hpp"

// ready_系の関数では格納を行なっているが
// ready系の関数が二つあるのはtestconfig2のようなserverblockの要素が
// 後に存在してしまう可能性があるため
// serverblockの情報の取得→locationblockの情報を取得
// 上記の流れを行いたい場合どうしても二回開く必要がある（要相談

void	Config::set_serverconfig_ready_next_serverconfig(AllConfig *Configs, \
															ServerConfig *server_config, \
															std::vector<std::string> *field_header_map, \
															std::vector<std::vector<std::string> > *server_name_list)
{
	Configs->set_host_config(*server_config);
	server_name_list->push_back(server_config->get_server_names());
	this->_all_configs[server_config->get_server_names()] = *Configs;
	Configs->clear_information();
	server_config->clear_serverconfig();
	field_header_map->clear();
}

bool	Config::ready_server_config_format(const std::string &config_file_name, \
											std::vector<std::vector<std::string> > *server_name_list)
{
	AllConfig	Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool	in_server_block = false;
	bool	in_location_block = false;
	ServerConfig	server_config;
	std::ifstream	config_lines(config_file_name.c_str());
	std::string		config_line;
	std::vector<std::string>	field_header_map;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_ignore_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_server_block(config_line))
			in_server_block = true;
		else if (in_server_block == true && in_location_block == false && \
		IsConfigFormat::ready_server_block_format(config_line, &in_server_block, &server_config, &field_header_map))
		{
			if (IsConfigFormat::is_start_location_block(config_line))
				in_location_block = true;
			else if (ConfigHandlingString::is_block_end(config_line))
				set_serverconfig_ready_next_serverconfig(&Configs, &server_config, &field_header_map, server_name_list);
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::is_location_block_config(config_line, &in_location_block))
			continue;
		else  // 上記3つ以外の場合、状況としてはありえないためfalseになる
			return this->report_errorline(config_line);
	}
	return (in_server_block == false && in_location_block == false);
}

void	Config::ready_next_locationconfig(LocationConfig *location_config, \
												const std::vector<std::string> &server_name, \
												bool *in_server_block)
{
	location_config->clear_location_keyword();
	location_config->set_server_block_infs(this->get_same_allconfig(server_name).get_host_config());
	*in_server_block = true;
}

bool	Config::ready_location_config(const std::string &config_file_name, \
										std::vector<std::vector<std::string> >::iterator server_name_itr)
{
	std::vector<std::string>	location_field_header_map;
	std::ifstream	config_lines(config_file_name.c_str());
	std::string	config_line;
	std::string	location_path;
	LocationConfig	location_config;
	bool	in_server_block = false;
	bool	in_location_block = false;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_ignore_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_server_block(config_line))
			ready_next_locationconfig(&location_config, *server_name_itr, &in_server_block);
		else if (in_server_block == true && in_location_block == false)
		{
			if (IsConfigFormat::is_start_location_block(config_line, &location_path))
				in_location_block = true;
			else if (ConfigHandlingString::is_block_end(config_line))
				server_name_itr++;
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::ready_location_block_config(config_line, &in_location_block, &location_config, &location_field_header_map))
		{
			if (ConfigHandlingString::is_block_end(config_line))
			{
				this->_all_configs[*server_name_itr].set_location_config(location_path, location_config);
				location_field_header_map.clear();
				location_config.clear_location_keyword();
				location_config.set_server_block_infs(this->get_same_allconfig(*server_name_itr).get_host_config());
			}
		}
		else
			return this->report_errorline(config_line);
	}
	return (true);
}

Config::Config(const std::string &config_file_name): _is_config_format(false)
{
	std::ifstream	test_open(config_file_name.c_str());
	std::vector<std::vector<std::string> >	server_name_list;
	bool	server_success, location_success;

	if (!(test_open.is_open()))
		return ;
	server_success = this->ready_server_config_format(config_file_name, &server_name_list);
	if (!server_success)
		return;
	location_success = this->ready_location_config(config_file_name, server_name_list.begin());
	if (!location_success)
		return;
	this->_is_config_format = true;
}

Config::~Config(){}

std::map<std::vector<std::string>, AllConfig>	Config::get_all_configs()
{
	return (this->_all_configs);
}

// bool	Config::is_vector_equal(const std::vector<std::string> &servername, const std::vector<std::string> &inputed_servername)
// {
// 	std::vector<std::string>::iterator	servername_itr = servername.begin();

// 	while (servername_itr != servername.end())
// 	{
// 		if (std::count(inputed_servername.begin(), inputed_servername.end(), *servername_itr) != 1)
// 			return false;
// 		servername_itr++;
// 	}
// 	return (true);
// }

// bool	Config::is_server_name_exist(const std::vector<std::string> &servername)
// {
// 	std::map<std::vector<std::string>, AllConfig>::iterator	all_configs_itr = this->_all_configs.begin();

// 	while (all_configs_itr != this->_all_configs.end())
// 	{
// 		if (is_vector_equal(servername, all_configs_itr->first))
// 			return true;
// 		all_configs_itr++;
// 	}
// 	return false;
// }

AllConfig Config::get_same_allconfig(const std::vector<std::string> &server_name)
{
	return (this->_all_configs[server_name]);
}

bool Config::report_errorline(const std::string &config_line)
{
	std::cerr << "FORMAT ERROR OCURED" << std::endl;
	std::cerr << "|====== TARGET LINE ======|" << std::endl;
	std::cerr << "|" << config_line << std::endl;
	std::cerr << "|=========================|" << std::endl;
	return (false);
}
