#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include "webserv.hpp"
#include "ConfigStruct.hpp"
#include "Config.hpp"
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "FileHandler.hpp"
#include "HttpResponse.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"


bool HttpResponse::is_cgi_file() const {
    Result<bool, int> result = Config::is_cgi_mode_on(this->server_config_,
                                                      this->request_.request_target());
    if (result.is_err()) {
        return false;
    }
    bool cgi_mode = result.get_ok_value();
    if (!cgi_mode) {
        return false;
    }
    return Config::is_cgi_extension(this->server_config_,
                                    this->request_.request_target());
}


void HttpResponse::get_error_page_to_body() {
    this->body_buf_.clear();

    // get_error_page_path
    DEBUG_PRINT(CYAN, "  get_error_page 1 target: %s, status_code: %d",
                this->request_.request_target().c_str(), this->status_code());
    Result<std::string, int> result;
    result = Config::get_error_page_path(this->server_config_,
                                         this->request_.request_target(),
                                         this->status_code());
    if (result.is_err()) {
        DEBUG_PRINT(CYAN, "  get_error_page 2 -> err");
        return;
    }
    DEBUG_PRINT(CYAN, "  get_error_page 3");
    std::string error_page_path = result.get_ok_value();
    DEBUG_PRINT(CYAN, "  get_error_page 4 error_page_path: %s", error_page_path.c_str());

    std::map<std::string, std::string> mime_types;  // todo
    mime_types["html"] = "text/html";
    mime_types["htm"] = "text/htm";
    mime_types["jpg"] = "text/htm";

    get_file_content(error_page_path, &this->body_buf_);
}


std::string HttpResponse::get_indexed_path() {
    std::string resource_path = HttpResponse::get_resource_path();

    Result<std::string, int> index_exist = Config::get_index(this->server_config_,
                                                             this->request_.request_target());
    if (index_exist.is_err()) {
        DEBUG_PRINT(CYAN, "index nothing");
        return resource_path;
    }
    std::string index_page = index_exist.get_ok_value();
    std::string extension = StringHandler::get_extension(resource_path);
    DEBUG_PRINT(CYAN, "index_page: %s", index_page.c_str());

    std::string indexed_path = resource_path;
    if (extension.empty()) {
        indexed_path.append(index_page);
    }
    return indexed_path;
}


bool HttpResponse::is_redirect() const {
    Result<bool, int> result = Config::is_redirect(this->server_config_,
                                                   this->request_.request_target());
    return result.is_ok() && result.get_ok_value();
}


StatusCode HttpResponse::get_redirect_content(std::map<std::string, std::string> *headers) {
    if (!headers) { return InternalServerError; }

    Result<ReturnDirective, int> redirect_result = Config::get_redirect(this->server_config_,
                                                                        this->request_.request_target());
    if (redirect_result.is_err()) {
        return BadRequest;
    }
    ReturnDirective redirect = redirect_result.get_ok_value();

    Result<HostPortPair, StatusCode> info_result = this->request_.server_info();
    if (info_result.is_err()) {
        return info_result.get_err_value();
    }

    HostPortPair server_info = info_result.get_ok_value();
    std::string location = "http://";

    location.append(server_info.first);
    location.append(":");
    if (!server_info.second.empty()) {
        location.append(server_info.second);
    } else {
        location.append(this->address_port_pair_.first);
    }
    location.append(redirect.text);

    (*headers)[LOCATION] = location;
    return redirect.code;
}


StatusCode HttpResponse::get_request_body() {
    Result<bool, int> autoindex_result;
    autoindex_result = Config::is_autoindex_on(this->server_config_,
                                               this->request_.request_target());
    if (autoindex_result.is_err()) {
        return BadRequest;
    }
    bool autoindex = autoindex_result.get_ok_value();

    std::string indexed_path = get_indexed_path();
    DEBUG_PRINT(CYAN, "  file_path: %s, autoindex: %s", indexed_path.c_str(), autoindex ? "on" : "off");


    Result<bool, StatusCode> is_dir_result = FileHandler::is_directory(indexed_path);
    if (is_dir_result.is_err()) {
        StatusCode error_code = is_dir_result.get_err_value();
        return error_code;
    }
    bool is_directory = is_dir_result.get_ok_value();
    if (is_directory) {
        if (autoindex) {
            DEBUG_PRINT(CYAN, "  get_content -> directory_listing");
            return get_directory_listing(indexed_path, &this->body_buf_);
        } else {
            DEBUG_PRINT(CYAN, "  get_content -> directory -> 404");
            return NotFound;
        }
    } else if (is_cgi_file()) {
        DEBUG_PRINT(CYAN, "  get_content -> cgi");
        return this->cgi_handler_.exec_script(indexed_path);
    } else if (is_redirect()) {
        return get_redirect_content(&this->headers_);
    } else {
        DEBUG_PRINT(CYAN, "  get_content -> file_content");
        return get_file_content(indexed_path, &this->body_buf_);
    }
}
