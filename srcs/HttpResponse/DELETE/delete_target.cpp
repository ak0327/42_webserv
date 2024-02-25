#include "ConfigStruct.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpResponse.hpp"

StatusCode HttpResponse::delete_target() {
    std::string target_path = HttpResponse::get_resource_path();
    DEBUG_PRINT(YELLOW, " DELETE path: %s", target_path.c_str());

    FileHandler file(target_path);
    return file.delete_file();
}
