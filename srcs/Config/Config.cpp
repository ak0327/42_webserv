#include "Config.hpp"

bool	Config::ready_server_config_format(const std::string &config_file_name, std::vector<std::vector<std::string> > *servername_list)
{
	std::ifstream	config_lines(config_file_name.c_str());
	std::string		config_line;
	std::string		location_path;
	ServerConfig	serverconfig;
	LocationConfig							locationconfig;
	AllConfig								Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool			in_server_block = false;
	bool			in_location_block = false;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((ConfigHandlingString::is_nomeanig_line(config_line)))
			continue;
		if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_serverblock(config_line))
			in_server_block = true;
		else if (in_server_block == true && in_location_block == false && \
		IsConfigFormat::is_serverblock_format(config_line, &in_server_block, &in_location_block, &serverconfig, &location_path))
		{
			if (HandlingString::obtain_without_ows_value(config_line) == "}")
			{
				Configs.set_host_config(serverconfig);
				servername_list->push_back(serverconfig.get_server_name());
				this->_all_configs[serverconfig.get_server_name()] = Configs;
				Configs.clear_information();
				serverconfig.clear_serverconfig();
			}
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::is_locationblock_format(config_line, &in_location_block, &locationconfig))
		{
			if (HandlingString::obtain_without_ows_value(config_line) == "}")
			{
				Configs.set_location_config(location_path, locationconfig);
			}
		}
		else  // 上記3つ以外の場合、状況としてはありえないためfalseになる
		{
			std::cout << "config line is -> " << config_line << std::endl;
			return (false);
		}
	}
	return (true);
}

void	Config::ready_location_config(const std::string &config_file_name, std::vector<std::vector<std::string> > servername_list)
{
	std::vector<std::vector<std::string> >::iterator servername_itr = servername_list.begin();
	std::ifstream	config_lines(config_file_name.c_str());  // 変更が反映されない
	std::string		config_line;
	std::string		location_path;
	ServerConfig	serverconfig;
	LocationConfig	locationconfig;
	AllConfig		Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool			in_server_block = false;
	bool			in_location_block = false;

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
		else if (in_server_block == true && in_location_block == false && \
		IsConfigFormat::is_serverblock_format(config_line, &in_server_block, &in_location_block, &serverconfig, &location_path))
		{
			if (HandlingString::obtain_without_ows_value(config_line) == "}")
				servername_itr++;
		}
		else if (in_server_block == true && in_location_block == true && \
		IsConfigFormat::is_locationblock_format(config_line, &in_location_block, &locationconfig))
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
	std::ifstream							test_open(config_file_name.c_str());
	std::vector<std::vector<std::string> >	servername_list;

	if (!(test_open.is_open() && this->ready_server_config_format(config_file_name, &servername_list)))
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
