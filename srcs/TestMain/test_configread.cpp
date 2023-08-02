#include "../includes/Config.hpp"
#include "../includes/HandlingString.hpp"
#include "../includes/LocationConfig.hpp"
#include "../includes/ServerConfig.hpp"

int main()
{
	try
	{
		Config config("../../config/testconfig1.conf");
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
	}
}