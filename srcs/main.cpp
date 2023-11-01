#include <cstdlib>
#include <iostream>
#include <string>
#include "webserv.hpp"
#include "Debug.hpp"

namespace {
	int CONFIG_FILE_INDEX = 1;
	int EXECUTABLE_FILE_ONLY_ARGC = 1;
	int CONFIG_FILE_GIVEN_ARGC = 2;
	std::string INVALID_ARGUMENT_ERROR_MSG = "[Error] invalid argument";

	void validate_argc(int argc) {
		if (argc == EXECUTABLE_FILE_ONLY_ARGC) {
			return;
		}
		if (argc == CONFIG_FILE_GIVEN_ARGC) {
			return;
		}
		throw std::invalid_argument(INVALID_ARGUMENT_ERROR_MSG);
	}
}  // namespace

int main(int argc, char **argv) {
	std::string		config_file_path;
	// Config	config;  // todo
	// Server			server;  // todo

	try {
		validate_argc(argc);
		config_file_path = get_valid_config_file_path(argv[CONFIG_FILE_INDEX]);
		DEBUG_PRINT("config_file_path=[%s]", config_file_path.c_str());

		// if path is 'default', config set to default
		// config = Config(config_file_path);

		// server = Server.start_up(config);  // load config and setup socket
		// server.run();  // connect to client
	}
	catch (std::exception const &e) {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
