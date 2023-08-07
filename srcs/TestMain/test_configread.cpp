#include "../includes/HandlingString.hpp"
#include "../includes/ServerConfig.hpp"
#include "../includes/Config.hpp"

int main(int argc, char **argv)
{
	if (argc == 1)
	{
		std::cout << "YOU MUST INPUT FILE NAME" << std::endl;
		return (1);
	}
	else if (argc != 2)
	{
		std::cout << "ARGMENT IS 2 ONLY" << std::endl;
		return (1);
	}
	try
	{
		Config config(argv[argc - 1]);
		config.show_configinfos();
	}
	catch(Config::ConfigError e)
	{
		std::cerr << e.what() << '\n';
	}
	catch(ServerConfig::ConfigSyntaxError e)
	{
		std::cerr << e.what() << '\n';
	}
	catch(ServerConfig::ServerKeywordError e)
	{
		std::cerr << e.what() << '\n';
	}
}