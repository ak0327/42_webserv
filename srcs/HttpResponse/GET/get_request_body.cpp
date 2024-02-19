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

	if (stat(path.c_str(), &stat_buf) == STAT_ERROR) {
		return false;
	}
	return S_ISDIR(stat_buf.st_mode);  // todo: permission
}


bool HttpResponse::is_cgi_file(const std::string &path) {  // todo: config method
	const std::string extension = StringHandler::get_extension(path);
	return extension == "py" || extension == "php";
}


Result<int, int> HttpResponse::get_path_content(const std::string &path, bool autoindex) {
    Result<int, int> result;
    std::map<std::string, std::string> mime_types;
    mime_types["html"] = "text/html";
    mime_types["htm"] = "text/htm";

    if (autoindex && is_directory(path)) {
        result = get_directory_listing(path, &this->body_buf_, &this->status_code_);
    } else if (is_cgi_file(path)) {
        // todo ------------------
        // create_cgi_request();
        // get_cgi_response();
        // get_cgi_field_lines();
        // get_cgi_request_body();
        // -----------------------
        result = exec_cgi(path, &this->cgi_read_fd_, &this->cgi_pid_, &this->status_code_);
    } else {
        result = get_file_content(path, mime_types, &this->body_buf_, &this->status_code_);
    }
    return result;
}


void HttpResponse::get_error_page() {
    // get_error_page_path
    Result<std::string, int> result = Configuration::get_error_page(this->server_config_,
                                                                    this->request_.get_request_target(),
                                                                    this->status_code_);
    if (result.is_err()) {
        return;
    }
    std::string error_page_path = result.get_ok_value();
    std::map<std::string, std::string> mime_types;  // todo
    int unused;
    get_file_content(error_page_path, mime_types, &this->body_buf_, &unused);
}




Result<Fd, int> HttpResponse::get_request_body(const std::string &target_path) {
    Result<bool, int> autoindex_result = Configuration::is_autoindex_on(this->server_config_,
                                                                        this->request_.get_request_target());

    if (autoindex_result.is_err()) {
        this->status_code_ = STATUS_BAD_REQUEST;  // bad target
        return Result<Fd, int>::err(ERR);
    }
    bool autoindex = autoindex_result.get_ok_value();
    return get_path_content(target_path, autoindex);  // todo: mime_type
}
