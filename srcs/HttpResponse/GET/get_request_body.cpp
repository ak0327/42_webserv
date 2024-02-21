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
#include "Configuration.hpp"
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
    // get_error_page_path
    DEBUG_PRINT(CYAN, "  get_error_page 1 target: %s, code: %d", this->request_.request_target().c_str(), code);
    Result<std::string, int> result;
    result = Configuration::get_error_page_path(this->server_config_,
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


Result<ProcResult, StatusCode> HttpResponse::get_request_body(const std::string &target_path) {
    Result<bool, int> autoindex_result;
    autoindex_result = Configuration::is_autoindex_on(this->server_config_,
                                                      this->request_.request_target());
    if (autoindex_result.is_err()) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }
    bool autoindex = autoindex_result.get_ok_value();
    DEBUG_PRINT(CYAN, "  target_path: %s, autoindex: %s", target_path.c_str(), autoindex ? "on" : "off");

    DEBUG_PRINT(CYAN, "  is_dir: %s", is_directory(target_path) ? "true" : "false");
    Result<ProcResult, StatusCode> result;
    if (autoindex && is_directory(target_path)) {
        DEBUG_PRINT(CYAN, "  get_content -> directory_listing");
        result = get_directory_listing(target_path, &this->body_buf_);
    } else if (is_cgi_file(target_path)) {
        DEBUG_PRINT(CYAN, "  get_content -> cgi");
        // todo ------------------
        // create_cgi_request();
        // get_cgi_response();
        // get_cgi_field_lines();
        // get_cgi_request_body();
        // -----------------------
        result = exec_cgi(target_path, &this->cgi_read_fd_, &this->cgi_pid_);
    } else {
        DEBUG_PRINT(CYAN, "  get_content -> file_content");
        result = get_file_content(target_path, &this->body_buf_);
    }
    return result;
}
