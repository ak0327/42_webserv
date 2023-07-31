/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Config.cpp                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user <user@student.42.fr>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/07/30 02:04:06 by user              #+#    #+#             */
/*   Updated: 2023/07/31 20:46:24 by user             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/Config.hpp"

Config::Config(std::string const &conf)
{
	std::ifstream conf_file(conf);

	if (conf_file.is_open() == false)
		throw	Config::ConfigError();
}

Config::~Config(){}