#include "../includes/HandlingString.hpp"
#include "../includes/ServerConfig.hpp"
#include "../includes/Config.hpp"

int main()
{
	try
	{
		Config config("config/testconfig1.conf");
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