#include "Config.hpp"

bool	Config::is_config_format(const std::string &config_file_name)
{
	std::ifstream	config_lines(config_file_name);
	std::string		config_line;
	std::string		location_path;
	ServerConfig	serverconfig;
	LocationConfig	locationconfig;
	AllConfig		Configs;  // 現状ここに対する適切な変数が見つかっていない
	bool			in_server_block = false;
	bool			in_location_block = false;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if (!(ConfigHandlingString::is_nomeanig_line(config_line)))
		{
			if (in_server_block == false && in_location_block == false && IsConfigFormat::is_start_serverblock(config_line))
				in_server_block = true;
			else if (in_server_block == true && in_location_block == false && \
			IsConfigFormat::is_serverblock_format(config_line, &in_server_block, &in_location_block, &serverconfig, &location_path))
			{
				if (HandlingString::obtain_without_ows_value(config_line) == "}")
				{
					Configs.set_host_config(serverconfig);
					this->_all_configs[serverconfig.get_server_name()] = Configs;
					Configs.clear_information();
					serverconfig.clear_serverconfig();
				}
			}
			else if (in_server_block == true && in_location_block == true && \
			IsConfigFormat::is_locationblock_format(config_line, &in_location_block, &locationconfig))
			{
				if (HandlingString::obtain_without_ows_value(config_line) == "}")
					Configs.set_location_config(location_path, locationconfig);
			}
			else  // 上記3つ以外の場合、状況としてはありえないためfalseになる
				return (false);
		}
	}
	return (true);
}

Config::Config(const std::string &config_file_name): _is_config_format(true)
{
	std::ifstream	test_open(config_file_name);

	if (!(test_open.is_open() && this->is_config_format(config_file_name)))
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
