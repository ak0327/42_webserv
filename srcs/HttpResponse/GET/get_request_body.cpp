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
#include "HttpResponse.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"


bool HttpResponse::is_directory(const std::string &path) {
	struct stat	stat_buf = {};

    DEBUG_PRINT(CYAN, "path: %s", path.c_str());
	if (stat(path.c_str(), &stat_buf) == STAT_ERROR) {
        DEBUG_PRINT(CYAN, "stat error");
        return false;
	}
	return S_ISDIR(stat_buf.st_mode);  // todo: permission
}


bool HttpResponse::is_cgi_file(const std::string &path) {  // todo: config method
	const std::string extension = StringHandler::get_extension(path);
	return extension == "py" || extension == "php";
}


void HttpResponse::get_error_page(const StatusCode &code) {
    this->body_buf_.clear();

    // get_error_page_path
    DEBUG_PRINT(CYAN, "  get_error_page 1 target: %s, code: %d", this->request_.request_target().c_str(), code);
    Result<std::string, int> result;
    result = Config::get_error_page_path(this->server_config_,
                                         this->request_.request_target(),
                                         code);
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


std::string HttpResponse::get_indexed_path(const std::string &resource_path) {
    Result<std::string, int> index_exist = Config::get_index(this->server_config_,
                                                             this->request_.request_target());
    if (index_exist.is_err()) {
        return resource_path;
    }
    std::string index_page = index_exist.get_ok_value();
    std::string extension = StringHandler::get_extension(resource_path);

    std::string indexed_path = resource_path;
    if (extension.empty()) {
        indexed_path.append(index_page);
    }
    return indexed_path;
}


StatusCode HttpResponse::get_request_body(const std::string &resource_path) {
    Result<bool, int> autoindex_result;
    autoindex_result = Config::is_autoindex_on(this->server_config_,
                                               this->request_.request_target());
    if (autoindex_result.is_err()) {
        return BadRequest;
    }
    bool autoindex = autoindex_result.get_ok_value();

    std::string indexed_path = get_indexed_path(resource_path);
    DEBUG_PRINT(CYAN, "  file_path: %s, autoindex: %s", indexed_path.c_str(), autoindex ? "on" : "off");

    if (is_directory(indexed_path)) {
        if (autoindex) {
            DEBUG_PRINT(CYAN, "  get_content -> directory_listing");
            return get_directory_listing(resource_path, &this->body_buf_);
        } else {
            DEBUG_PRINT(CYAN, "  get_content -> directory -> 404");
            return NotFound;
        }
    }

    if (is_cgi_file(indexed_path)) {
        DEBUG_PRINT(CYAN, "  get_content -> cgi");
        return exec_cgi(indexed_path, &this->cgi_read_fd_, &this->cgi_pid_);
    } else {
        DEBUG_PRINT(CYAN, "  get_content -> file_content");
        return get_file_content(indexed_path, &this->body_buf_);
    }
}
