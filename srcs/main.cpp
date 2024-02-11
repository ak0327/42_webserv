#include <cstdlib>
#include <iostream>
#include <string>
#include "webserv.hpp"
#include "Configuration.hpp"
#include "Debug.hpp"
#include "Server.hpp"

namespace {

int CONFIG_FILE_INDEX = 1;
int CONFIG_FILE_GIVEN_ARGC = 2;

void validate_argc(int argc) {
	const std::string INVALID_ARGUMENT_ERROR_MSG = "[Error] invalid argument";

	if (argc == CONFIG_FILE_GIVEN_ARGC) {
		return;
	}
	throw std::invalid_argument(INVALID_ARGUMENT_ERROR_MSG);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
	try {
		validate_argc(argc);

        char *config_file_path = argv[CONFIG_FILE_INDEX];
		DEBUG_PRINT("config_file_path=[%s]", config_file_path);
		Configuration config(config_file_path);

		Server server = Server(config);
		server.process_client_connection();
	}
	catch (std::exception const &e) {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
