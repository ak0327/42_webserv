#include "Config.hpp"

// ready_系の関数では格納を行なっているが
// ready系の関数が二つあるのはtestconfig2のようなserverblockの要素が
// 後に存在してしまう可能性があるため
// serverblockの情報の取得→locationblockの情報を取得
// 上記の流れを行いたい場合どうしても二回開く必要がある（要相談

void	Config::set_server_config_to_allconfigs(AllConfig	*Configs, \
											ServerConfig	*server_config, \
					std::vector<std::vector<std::string> >	*server_name_list)
{
	Configs->set_server_config(*server_config);
	server_name_list->push_back(server_config->get_server_name());
	this->_all_configs[server_config->get_server_name()] = *Configs;
}

void	Config::init_server_config_and_allconfigs(AllConfig	*Configs, \
											ServerConfig	*server_config, \
								std::vector<std::string>	*field_header_map)
{
	Configs->clear_information();
	server_config->clear_serverconfig();
	field_header_map->clear();
}

int	Config::server_block_action(const std::string	&config_line, \
											bool	*in_server_block, \
											bool	*in_location_block, \
										AllConfig	*Configs, \
									ServerConfig	*server_config, \
						std::vector<std::string>	*field_headers, \
			std::vector<std::vector<std::string> >	*server_name_list)
{
	if (IsConfigFormat::is_start_location_block(config_line))
	{
		*in_location_block = true;
		return IS_OK_START_SERVER_BLOCK;
	}
	if (ConfigHandlingString::is_block_end(config_line))
	{
		*in_server_block = false;
		set_server_config_to_allconfigs(Configs, server_config, server_name_list);
		init_server_config_and_allconfigs(Configs, server_config, field_headers);
		return IS_OK_BLOCK_END;
	}
	if (IsConfigFormat::is_server_block_format(config_line, *field_headers))
	{
		bool	done_input_action = IsConfigFormat::do_input_field_key_field_value(config_line, server_config, field_headers);
		if (done_input_action == false)
			return (IS_ALREADY_EXIST_FIELD_KEY);
		return IS_OK_IN_SERVER_BLOCK;
	}
	return (IS_NOT_SERVER_CONFIG_FORMAT);
}

bool	Config::ready_server_config(const std::string &config_file_name, \
											std::vector<std::vector<std::string> > *server_name_list)
{
	AllConfig	Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool	in_server_block = false;
	bool	in_location_block = false;
	ServerConfig	server_config;
	std::ifstream	config_lines(config_file_name.c_str());
	std::string		config_line;
	std::vector<std::string>	field_headers;
	size_t	line = 1;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_ignore_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false)
		{
			if (IsConfigFormat::is_start_server_block(config_line, &in_server_block) == false)
			{
				return this->report_errorline(config_line, line);
			}
		}
		else if (in_server_block == true && in_location_block == false)
		{
			int	result_server_block_action = server_block_action(config_line, &in_server_block, &in_location_block, \
																	&Configs, &server_config, &field_headers, \
																		server_name_list);
			if (result_server_block_action != IS_OK)
				return this->report_errorline(config_line, line);
		}
		else if (in_server_block == true && in_location_block == true)
		{
			if (ConfigHandlingString::is_block_end(config_line))
				in_location_block = false;
			else if (IsConfigFormat::is_location_block_format(config_line) == false)
				return this->report_errorline(config_line, line);
		}
		else
			return this->report_errorline(config_line, line);
		line++;
	}
	return (in_server_block == false && in_location_block == false);
}

void	Config::init_location_config_with_server_config(LocationConfig *location_config, \
												const std::vector<std::string> &server_name, \
												bool *in_server_block)
{
	location_config->clear_location_keyword();
	location_config->set_server_block_infs(this->get_same_allconfig(server_name).get_server_config());
	*in_server_block = true;
}

bool	Config::ready_location_config(const std::string &config_file_name, \
										std::vector<std::vector<std::string> >::iterator server_name_itr)
{
	std::vector<std::string>	location_field_headers;
	std::ifstream	config_lines(config_file_name.c_str());
	std::string	config_line, location_path;
	LocationConfig	location_config;
	bool	in_server_block = false;
	bool	in_location_block = false;
	size_t	line = 1;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_ignore_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false)
		{
			IsConfigFormat::is_start_server_block(config_line, &in_server_block);
			if (in_server_block == true)
				init_location_config_with_server_config(&location_config, \
														*server_name_itr, &in_server_block);
		}
		else if (in_server_block == true && in_location_block == false)
		{
			if (IsConfigFormat::is_start_location_block(config_line, &location_path))
				in_location_block = true;
			else if (ConfigHandlingString::is_block_end(config_line))
				server_name_itr++;
		}
		else if (in_server_block == true && in_location_block == true)
		{
			if (ConfigHandlingString::is_block_end(config_line))
			{
				this->_all_configs[*server_name_itr].set_location_config(location_path, location_config);
				location_field_headers.clear();
				location_config.clear_location_keyword();
				location_config.set_server_block_infs(this->get_same_allconfig(*server_name_itr).get_server_config());
				in_location_block = false;
			}
			else if (IsConfigFormat::is_location_block_format(config_line))
			{
				bool	done_input_action = IsConfigFormat::do_input_field_key_field_value(config_line, &location_config, &location_field_headers);
				if (done_input_action == false)
					return this->report_errorline(config_line, line);
			}
			else
				return this->report_errorline(config_line, line);
		}
		else
			return this->report_errorline(config_line, line);
		line++;
	}
	return (true);
}

Config::Config(const std::string &config_file_name): _is_config_format(false)
{
	std::ifstream	test_open(config_file_name.c_str());
	std::vector<std::vector<std::string> >	server_name_list;
	bool	server_success, location_success;

	if (!(test_open.is_open()))
		return;
	server_success = this->ready_server_config(config_file_name, &server_name_list);
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

AllConfig Config::get_same_allconfig(const std::vector<std::string> &server_name)  // これがconfigの読み取りの時に使うやつ
{
	return (this->_all_configs[server_name]);
}

AllConfig Config::get_same_allconfig(const std::string &server_name)  // これがrequestように使うやつ
{
	std::string	server_name_without_port;
	std::vector<std::string>	all_config_server_names;
	std::map<std::vector<std::string>, AllConfig>::iterator	all_configs_itr = this->_all_configs.begin();
	size_t	key_counter = 0;

	if (server_name.find(':') != std::string::npos)
		server_name_without_port = server_name.substr(server_name.find(':'));
	else
		server_name_without_port = server_name;
	while (all_configs_itr != this->_all_configs.end())
	{
		all_config_server_names = all_configs_itr->first;
		if (std::find(all_config_server_names.begin(), all_config_server_names.end(), server_name) != all_config_server_names.end())
			return (all_configs_itr->second);
		all_configs_itr++;
		key_counter++;
	}
	if (key_counter == 0)
		return (AllConfig());
	else
		return (this->_all_configs.begin()->second);
}

bool Config::report_errorline(const std::string &config_line, const size_t &line)
{
	std::cerr << "FORMAT ERROR OCURED" << std::endl;
	std::cerr << "|====== TARGET LINE ======|" << std::endl;
	std::cerr << "* line -> " << line << " |" << config_line << "|" << std::endl;
	std::cerr << "|=========================|" << std::endl;
	return (false);
}
