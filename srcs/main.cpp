#include <cstdlib>
#include <iostream>
#include <string>
#include "webserv.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "Server.hpp"

namespace {


const int kDefaultConfigFileUseArgc = 1;
const int kConfigFileGivenArgc = 2;
const std::size_t kConfigFileGivenIndex = 1;
const char kDefaultConfigPath[] = "conf/webserv.conf";

const char *get_config_file_path(int argc, char **argv) {
    if (argc == kDefaultConfigFileUseArgc) {
        return kDefaultConfigPath;
    }
    if (argc == kConfigFileGivenArgc) {
        return argv[kConfigFileGivenIndex];
    }
    return NULL;
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
    const char *config_file_path = get_config_file_path(argc, argv);
    if (!config_file_path) {
        std::cerr << "Usage: ./webserv  [path_to_configuration_file.conf]" << std::endl;
        return EXIT_FAILURE;
    }
    DEBUG_PRINT(WHITE, "config_file_path=[%s]", config_file_path);

    Config config(config_file_path);
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


#ifdef LEAKS

__attribute__((destructor))
static void	destructor(void)
{
	system("leaks -q webserv");
}

#endif
