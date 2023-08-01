/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Config.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user <user@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/30 02:04:06 by user              #+#    #+#             */
/*   Updated: 2023/08/01 22:28:46 by user             ###   ########.fr       */
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
		server_config.serverkeyword_ch(line);
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