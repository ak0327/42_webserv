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

}  // namespace

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
    if (argc != CONFIG_FILE_GIVEN_ARGC) {
        std::cerr << "[Error] invalid argument" << std::endl;
        return EXIT_FAILURE;
    }
    char *config_file_path = argv[CONFIG_FILE_INDEX];
    DEBUG_PRINT("config_file_path=[%s]", config_file_path);

    Configuration config(config_file_path);
    Result<int, std::string> config_result = config.get_result();
    if (config_result.is_err()) {
        const std::string error_msg = config_result.get_err_value();
        std::cerr << error_msg << std::endl;
        return EXIT_FAILURE;
    }

    Server server(config);

    ServerResult init_result = server.init();
    if (init_result.is_err()) {
        const std::string error_msg = init_result.get_err_value();
        std::cerr << "[Error] " << error_msg << std::endl;
        return EXIT_FAILURE;
    }

    ServerResult server_result = server.run();
    if (server_result.is_err()) {
        const std::string error_msg = server_result.get_err_value();
        std::cerr << "[Error] " << error_msg << std::endl;
        return EXIT_FAILURE;
    }
	return EXIT_SUCCESS;
}
