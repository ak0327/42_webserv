#include <cstdlib>
#include <iostream>
#include <string>
#include "webserv.hpp"
#include "Debug.hpp"
#include "Server.hpp"

namespace {
	int CONFIG_FILE_INDEX = 1;
	// int EXECUTABLE_FILE_ONLY_ARGC = 1;
	int CONFIG_FILE_GIVEN_ARGC = 2;
	std::string INVALID_ARGUMENT_ERROR_MSG = "[Error] invalid argument";

	const char *SERVER_IP = "127.0.0.1";
	const char *SERVER_PORT = "8080";

	void validate_argc(int argc) {
		// if (argc == EXECUTABLE_FILE_ONLY_ARGC) {
		// 	return;
		// }
		if (argc == CONFIG_FILE_GIVEN_ARGC) {
			return;
		}
		throw std::invalid_argument(INVALID_ARGUMENT_ERROR_MSG);
	}
}  // namespace

int main(int argc, char **argv) {
	std::string		config_file_path;
	// Configuration	config;  // todo

	try {
		validate_argc(argc);
		config_file_path = get_valid_config_file_path(argv[CONFIG_FILE_INDEX]);
		DEBUG_PRINT("config_file_path=[%s]", config_file_path.c_str());

		// config = Configuration(config_file_path);
		Server server = Server(SERVER_IP, SERVER_PORT);  // load config and setup socket
		server.process_client_connection();
	}
	catch (std::exception const &e) {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
