#include "Config.hpp"

bool	is_open_file(const std::string &target_file_name)
{
	std::ifstream tmp_open(target_file_name);

	if (!tmp_open.is_open())
		return (false);
	return (true);
}

//locationのスタートなら　location *.cgi {のように<OWS><文字列><SP><文字列><SP><{>のみ許容
//location内部なら　header<SP>*{文字列}<;>を許容　が、空白が一つかは不明
void	Config::handle_serverinfs(const std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos)
{
	if (HandlingString::skip_emptyword(line).find("location") != std::string::npos)  // locationaaaのような不備のある文字も通してしまっており、不適
		in_location = true;
	else if (HandlingString::skip_emptyword(line) == "}" && in_location == true)
		in_location = false;
	else if (HandlingString::skip_emptyword(line) == "}" && in_location == false)
	{
		if (server_config.get_port() == "")
			throw ServerConfig::ConfigServerdhirecthiveError();
		server_config.value_check();
		this->server_configs[server_config.get_port() + '_' + server_config.get_servername()[0]] = server_config;
		in_server = false;
	}
	else
		server_config.serverkeyword_insert(line, pos);
}

bool	is_location_start_format(const std::string &line);
{
	std::string		line_without_ows = HandlingString::obtain_withoutows_value(line);
	std::ifstream	location_parts(line_without_ows);  // <location> <*.cgi> <{> の<>内に存在しているそれぞれの文字の意味で名付けたい
	std::string		location_part;
	int				parts_counter = 0;

	while(std::getline(location_parts, location_part, ' '))
	{
		switch (parts_counter) 
		{
			case 0:
				if (location_part != "location")
					return false;
				else
					break;
			case 1:  //構成文字はprintableのみ？
				break;
			case 2:
				if (location_part != "{")
					return false;
				else
					break;
			default:
				return (false);
		}
		parts_counter++;
	}
	return (true);
}

void	Config::config_linecheck(const std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos)
{
	if (in_location == true && in_server == true)// locationの中 locationの中だからserverの中
	{
		if (HandlingString::skip_emptyword(line) == "}")
			in_location = false;
	}
	else if (in_server == true)// serverの中locationの外
		handle_serverinfs(line, in_server, in_location, server_config, pos);
	else
	{
		if (HandlingString::skip_emptyword(line) == "server{")
			in_server = true;
		else
			throw ServerConfig::ConfigSyntaxError(line, pos);
	}
}

bool	is_config_format(const std::string &target_file_name)
{
	std::ifstream	configfile_lines(target_file_name);
	std::string		line;
	size_t			pos = 1;
	bool			in_server = false;
	bool			in_location = false;

	while (std::getline(configfile_lines, line))
	{
		if (!(HandlingString::skip_emptyword(line)[0] == '#' || HandlingString::skip_emptyword(line) == ""))
			config_linecheck(line, in_server, in_location, server_config, config_line);;
		pos++;
	}
}

Config::Config(std::string const &configfile_name)
{
	std::ifstream	conf_file(configfile_name);
	std::string		line;
	ServerConfig	server_config;

	if (is_open_file(configfile_name) == false)
		return;
	if (is_config_format(configfile_name) == false)
		return;
	in_server= false;
	in_location = false;
	config_line = 1;
	std::ifstream	conf_file2(conf);
	LocationConfig	location_config;
	std::string		location_path = "";
	std::map<std::string, ServerConfig>::iterator	it = this->server_configs.begin();

	while (std::getline(conf_file2, line))
	{
		if (HandlingString::skip_emptyword(line)[0] == '#' || HandlingString::skip_emptyword(line) == "")
			;
		else
			config_location_check(line, in_server, in_location, location_config, location_path, it, config_line);
		config_line++;
	}
}

Config::~Config(){}
