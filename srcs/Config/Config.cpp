#include "Config.hpp"

Config::Config(std::string const &conf)
{
	std::ifstream conf_file_test(conf);


	if (!conf_file_test.is_open())
		throw	Config::ConfigError();

	std::ifstream	conf_file(conf);
	std::string		line;
	bool			in_server = false;
	bool			in_location = false;
	size_t			config_line = 1;
	ServerConfig	server_config;

	while (std::getline(conf_file, line))
	{
		if (HandlingString::skipping_emptyword(line)[0] == '#' || HandlingString::skipping_emptyword(line) == "")
			;
		else
			config_linecheck(line, in_server, in_location, server_config, config_line);
		config_line++;
	}

	in_server= false;
	in_location = false;
	config_line = 1;

	std::ifstream	conf_file2(conf);
	LocationConfig	location_config;
	std::string		location_path = "";
	std::map<std::string, ServerConfig>::iterator	it = this->server_configs.begin();

	while (std::getline(conf_file2, line))
	{
		if (HandlingString::skipping_emptyword(line)[0] == '#' || HandlingString::skipping_emptyword(line) == "")
			;
		else
			config_location_check(line, in_server, in_location, location_config, location_path, it, config_line);
		config_line++;
	}
}

Config::~Config(){}

void	Config::handle_serverinfs(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos)
{
	if (HandlingString::skipping_emptyword(line).find("location") != std::string::npos)
		in_location = true;
	else if (HandlingString::skipping_emptyword(line) == "}" && in_location == true)
		in_location = false;
	else if (HandlingString::skipping_emptyword(line) == "}" && in_location == false)
	{
		if (server_config.get_port() == "")
			throw ServerConfig::ConfigServerdhirecthiveError();
		server_config.value_check();
		this->server_configs[server_config.get_port() + '_' + server_config.get_servername()[0]] = server_config;
		// server_config.reset_content();
		in_server = false;
	}
	else
		server_config.serverkeyword_insert(line, pos);
}

void	Config::config_linecheck(std::string &line, bool &in_server, bool &in_location, ServerConfig &server_config, size_t pos)
{
	if (in_location == true && in_server == true)// locationの中 locationの中だからserverの中
	{
		if (HandlingString::skipping_emptyword(line) == "}")
			in_location = false;
	}
	else if (in_server == true)// serverの中locationの外
		handle_serverinfs(line, in_server, in_location, server_config, pos);
	else
	{
		if (HandlingString::skipping_emptyword(line) == "server{")
			in_server = true;
		else
			throw ServerConfig::ConfigSyntaxError(line, pos);
	}
}

bool	Config::handle_locationinfs(std::string &line, bool &in_location, LocationConfig &location_config, std::map<std::string, ServerConfig>::iterator &it, std::string &location_path)
{
	if (HandlingString::skipping_emptyword(line) == "}")
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
		if (HandlingString::skipping_emptyword(line).find("location") != std::string::npos)
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
			throw ServerConfig::ConfigSyntaxError(line, pos);
	}
}

// test用関数

// 　 ﾉ"′∧∧ ∧∧、ヽ､
// ((と(ﾟДﾟ三ﾟДﾟ)つ))　configの中身を見るぞーーー
// 　＼ヽﾐ　三　彡 ソ
// 　　 )ﾐ ､_　彡ノ
// 　　(ﾐ∪三∪彡
// 　　 ＼ヾ丿ノ
// 　　　 ヽ ﾉ
// 　　　　)ﾉ
// 　　　 ((

#define RESET_COLOR "\033[0m"
#define RED_COLOR "\033[31m"
#define GREEN_COLOR "\033[32m"
#define YELLOW_COLOR "\033[33m"
#define BLUE_COLOR "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR "\033[36m"

void	Config::show_configinfos()
{
	std::map<std::string, ServerConfig>::iterator	it = this->server_configs.begin();

	while (it != this->server_configs.end())
	{
		std::cout << "==============" << std::endl;
		std::cout << "|| port is -> " << RED_COLOR << it->first << RESET_COLOR << std::endl;
		std::cout << "==============" << std::endl;
		std::cout << "## SHOW SERVER CONFIG INFS## " << std::endl;
		it->second.show_serverconfig_allinfo();
		it++;
	}
}
