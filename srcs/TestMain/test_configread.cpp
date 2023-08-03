#include "../includes/HandlingString.hpp"
#include "../includes/ServerConfig.hpp"
#include "../includes/Config.hpp"

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