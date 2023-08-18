#include <cstdlib>
#include <iostream>
#include "webserv.hpp"

static void validate_argc(int argc) {
	if (argc == EXECUTABLE_FILE_ONLY_ARGC) {
		return;
	}
	if (argc == CONFIG_FILE_GIVEN_ARGC) {
		return;
	}
	throw std::invalid_argument(INVALID_ARGUMENT_ERROR_MSG);
}

int main(int argc, char **argv) {
	std::string		config_file_path;
	// Configuration	config;  // todo
	// Server			server;  // todo

	try {
		validate_argc(argc);
		config_file_path = get_valid_config_file_path(argc, argv);
		std::cout << "config_file_path=[" << config_file_path << "]" << std::endl;

		// if path is 'default', config set to default
		// config = Configuration(config_file_path);

		// server = Server.start_up(config);  // load config and setup socket
		// server.run();  // connect to client
	}
	catch (std::exception const &e) {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
