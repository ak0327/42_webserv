#include "Config.hpp"

std::string	Config::get_location_path(const std::string &locationfield_word)
{
	std::string			trim_emptyword = HandlingString::obtain_value(locationfield_word);
	std::stringstream	split_with_empty(trim_emptyword);
	std::string			location_path;
	split_with_empty >> location_path;
	split_with_empty >> location_path;  // location *.cgi {みたいに入ってきたときにstringstreamだと冗長な感じを受ける。。。気にしすぎ？
	return (location_path);
}

bool	Config::handle_locationinfs(std::string &line, bool &in_location, LocationConfig &location_config, std::map<std::string, ServerConfig>::iterator &it, std::string &location_path)
{
	if (HandlingString::skip_emptyword(line) == "}")
	{
		(server_configs[it->first]).set_locations(location_path, location_config);
		location_config.reset_locationconf(server_configs[it->first]);
		in_location = false;
	}
	else if (location_config.insert_location(line) == false)
		return (false);
	return (true);
}

void	Config::config_location_check(std::string &line, bool &in_server, bool &in_location, LocationConfig &location_config, std::string &location_path, \
std::map<std::string, ServerConfig>::iterator	&it, size_t &pos)
{
	if (in_location == true && in_server == true)  // locationの中 locationの中だからserverの中
		handle_locationinfs(line, in_location, location_config, it, location_path);
	else if (in_server == true)  // serverの中locationの外
	{
		if (HandlingString::skip_emptyword(line).find("location") != std::string::npos)
		{
			location_path = get_location_path(line);
			in_location = true;
		}
		else if (HandlingString::skip_emptyword(line) == "}")
		{
			// location_config.reset();
			in_server = false;
		}
	}
	else
	{
		if (HandlingString::skip_emptyword(line) == "server{")
			in_server = true;
		else
			throw ServerConfig::ConfigSyntaxError(line, pos);
	}
}
