#include "ConfigStruct.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpResponse.hpp"

StatusCode HttpResponse::delete_target() {
    if (!is_method_available()) {
        return MethodNotAllowed;
    }

    Result<std::string, StatusCode> indexed_result = Config::get_indexed_path(this->server_config_,
                                                                              this->request_.request_target());
    if (indexed_result.is_err()) {
        return indexed_result.err_value();
    }
    std::string path = indexed_result.ok_value();
    DEBUG_PRINT(YELLOW, " DELETE path: %s", path.c_str());

    FileHandler file(path);
    StatusCode result = file.delete_file();
    // std::cout << CYAN << "  delete result: " << result << RESET << std::endl;
    return result;
}
