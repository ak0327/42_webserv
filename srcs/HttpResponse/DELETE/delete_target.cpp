#include "ConfigStruct.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpResponse.hpp"


StatusCode HttpResponse::delete_target(const std::string &target) {
    Result<bool, int> delete_allowed = Config::is_method_allowed(this->server_config_,
                                                                 this->request_.request_target(),
                                                                 kDELETE);
    if (delete_allowed.is_err()) {
        return NotFound;
    }
    bool is_delete_allowed = delete_allowed.get_ok_value();
    if (!is_delete_allowed) {
        return MethodNotAllowed;
    }

    FileHandler file(target);
    return file.delete_file();
}
