/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Config.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user <user@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/30 02:04:06 by user              #+#    #+#             */
/*   Updated: 2023/08/02 01:41:36 by user             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/Config.hpp"

Config::Config(std::string const &conf)
{
	std::ifstream conf_file(conf);

	if (conf_file.is_open() == false)
		throw	Config::ConfigError();

	std::ifstream	conf_file(conf);
	std::string		line;
	bool			in_server= false;
	bool			in_location = false;
	size_t			config_line = 1;
	ServerConfig	server_config;

	while (std::getline(conf_file, line))
	{
		if (HandlingString::skipping_emptyword(line)[0] == '#' || HandlingString::skipping_emptyword(line) == "")
			;
		else
			config_linecheck(line, in_server, in_location, server_config);
		config_line++;
	}

	in_server= false;
	in_location = false;
	config_line = 1;

	std::ifstream	conf_file(conf);
	std::string		line;
	LocationConfig	location_config;
	std::string		location_path = "";
	std::map<std::string, ServerConfig>::iterator	it = this->server_configs.begin();

	while (std::getline(conf_file, line))
	{
		if (HandlingString::skipping_emptyword(line)[0] == '#' || HandlingString::skipping_emptyword(line) == "")
			;
		else
			config_location_check(line, in_server, in_location, location_config, location_path, it, config_line);
		config_line++;
	}
}

Config::~Config(){}

void	Config::handle_serverinfs(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config)
{
	if (HandlingString::skipping_emptyword(line) == "location{")
		in_location = true;
	else if (HandlingString::skipping_emptyword(line) == "}")
	{
		if (server_config.get_port() == "")
			throw ServerConfig::ConfigServerdhirecthiveError();
		this->server_configs[server_config.get_port() + '_' + server_config.get_servername()[0]] = server_config;
		// server_config.reset_content();
		in_server = false;
	}
	else
		server_config.serverkeyword_insert(line);
}

void	Config::config_linecheck(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config)
{
	if (in_location == true && in_server == true)// locationの中 locationの中だからserverの中
	{
		if (HandlingString::skipping_emptyword(line) == "}")
			in_location = false;
	}
	else if (in_server == true)// serverの中locationの外
		handle_serverinfs(line, in_server, in_location, server_config);
	else
	{
		if (HandlingString::skipping_emptyword(line) == "server{")
			in_server = true;
		else
			throw ServerConfig::ConfigSyntaxError();
	}
}

bool	Config::handle_locationinfs(std::string &line, bool &in_server, bool &in_location, LocationConfig &location_config, \
std::map<std::string, ServerConfig>::iterator	&it, std::string const &location_path, size_t pos)
{
	if (HandlingString::skipping_emptyword(line) == "}")
	{
		(server_configs[it->first]).set_locations(location_path, location_config);
		location_config.reset_locationconf(server_configs[it->first]);
		in_location = false;
	}
	else if (location_config.insert_location(line) == false)
	{
		HandlingString::error_show(line, pos);
		return (false);
	}
}

void	Config::config_location_check(std::string &line, bool &in_server, bool &in_location, LocationConfig &location_config, std::string &location_path, \
std::map<std::string, ServerConfig>::iterator	&it, size_t &pos)
{
	if (in_location == true && in_server == true)// locationの中 locationの中だからserverの中
		handle_locationinfs(line, in_server, in_location, location_config, it, location_path, pos);
	else if (in_server == true)// serverの中locationの外
	{
		if (HandlingString::skipping_emptyword(line) == "location{")
		{
			location_path = HandlingString::obtain_second_word(line);
			in_location = true;
		}
		else if (HandlingString::skipping_emptyword(line) == "}")
		{
			// location_config.reset();
			in_server = false;
		}
	}
	else
	{
		if (HandlingString::skipping_emptyword(line) == "server{")
			in_server = true;
		else
			throw ServerConfig::ConfigSyntaxError();
	}
}