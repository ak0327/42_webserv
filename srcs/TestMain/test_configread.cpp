#include "HandlingString.hpp"
#include "ServerConfig.hpp"
#include "Config.hpp"

int main()
{
	try
	{
		Config config("config/testconfig1.conf");
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
