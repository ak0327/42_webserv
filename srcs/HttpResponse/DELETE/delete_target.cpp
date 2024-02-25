#include "ConfigStruct.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpResponse.hpp"

StatusCode HttpResponse::delete_target(const std::string &target) {
    FileHandler file(target);
    return file.delete_file();
}
