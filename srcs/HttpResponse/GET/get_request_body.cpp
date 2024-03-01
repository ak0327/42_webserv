#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>
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
    DEBUG_PRINT(CYAN, "  get_error_page 1 target: %s, request_status: %d",
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


bool HttpResponse::is_redirect() const {
    Result<bool, int> result = Config::is_redirect(this->server_config_,
                                                   this->request_.request_target());
    return result.is_ok() && result.get_ok_value();
}


StatusCode HttpResponse::get_redirect_content(const ReturnDirective &redirect) {
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

    this->headers_[LOCATION] = location;
    return redirect.code;
}


bool HttpResponse::is_api_endpoint() {
    std::vector<std::string>::const_iterator itr;
    itr = std::find(API_ENDPOINTS.begin(), API_ENDPOINTS.end(), this->request_.request_target());
    return itr != API_ENDPOINTS.end();
}

bool HttpResponse::has_valid_index_page() {
    Result<std::string, StatusCode> indexed;
    indexed = Config::get_indexed_path(this->server_config_,
                                       this->request_.request_target());
    return indexed.is_ok();
}

bool HttpResponse::is_method_available() {
    Result<bool, int> allowed;
    allowed = Config::is_method_allowed(this->server_config_,
                                        this->request_.request_target(),
                                        this->request_.method());
    return allowed.is_ok() && allowed.get_ok_value();
}

bool HttpResponse::is_autoindex() {
    Result<bool, int> is_autoindex;
    is_autoindex = Config::is_autoindex_on(this->server_config_,
                                           this->request_.request_target());
    return is_autoindex.is_ok() && is_autoindex.get_ok_value();
}

bool HttpResponse::is_redirect_target() {
    Result<bool, int> is_redirect;
    is_redirect = Config::is_redirect(this->server_config_,
                                      this->request_.request_target());
    return is_redirect.is_ok() && is_redirect.get_ok_value();
}


StatusCode HttpResponse::redirect_to(const std::string &move_to) {
    ReturnDirective redirect;
    redirect.return_on = true;
    redirect.code = MovedPermanently;
    redirect.text = move_to;
    return get_redirect_content(redirect);
}


std::string HttpResponse::get_response_date() {
    char date[1024];
    time_t gmt_time;
    size_t n;
    std::string date_string;

    time(&gmt_time);
    n = std::strftime(date, 1024, "%a, %d %b %Y %X %Z", gmtime(&gmt_time));
    date_string = std::string(date, n);
    return date_string;
}


StatusCode HttpResponse::get_now() {
    const std::string head = "<!doctype html>\n"
                             "<html lang=\"ja\">\n"
                             "<head>\n"
                             "    <meta charset=\"UTF-8\">\n"
                             "    <title>now</title>\n"
                             "</head>\n"
                             "<body>\n";

    const std::string now = "Now: " + get_response_date();

    const std::string tail = "</body>\n"
                             "</html>";

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), now.begin(), now.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    return StatusOk;
}


StatusCode HttpResponse::response_api() {
    if (this->request_.request_target() == "/api/form-data") {
        return show_data();
    }
    if (this->request_.request_target() == "/api/show-body") {
        return show_body();
    }
    // if (this->request_.request_target() == "/api/upload") {
    //     return upload_file();
    // }
    if (this->request_.request_target() == "/api/now") {
        return get_now();
    }
    return NotFound;
}


// static
//   file      -> error / redirect / response
//   directory -> error / redirect / autoindex
// dynamic
//   cgi       -> error / response ; already branched out
//   api       -> error / response
StatusCode HttpResponse::get_request_body() {
    DEBUG_PRINT(YELLOW, "  GET 1 taget[%s]", this->request_.request_target().c_str());
    if (!is_method_available()) {
        DEBUG_PRINT(YELLOW, "  GET 2 err: 405");
        return MethodNotAllowed;
    }

    if (is_redirect_target()) {
        // return response_redirect();
        ReturnDirective redirect = Config::get_return(this->server_config_, this->request_.request_target());
        DEBUG_PRINT(YELLOW, "  GET 3 -> redirect");
        return get_redirect_content(redirect);
    }

    // api?
    //  Yes -> api
    if (is_api_endpoint()) {
        DEBUG_PRINT(YELLOW, "  GET 4 -> api");
        return response_api();
    }

    const std::string rooted_path = get_rooted_path();
    DEBUG_PRINT(YELLOW, "  GET 5 rooted_path[%s]", rooted_path.c_str());
    Result<bool, StatusCode> is_directory = FileHandler::is_directory(rooted_path);
    if (is_directory.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 6 err: directory");
        return is_directory.get_err_value();
    }
    if (is_directory.get_ok_value()) {
        DEBUG_PRINT(YELLOW, "  GET 7");
        const std::string &directory_path = rooted_path;
        if (!StringHandler::has_trailing_slash(directory_path)) {
            //  No -> 301
            DEBUG_PRINT(YELLOW, "  GET 8 -> redirect + /");
            const std::string with_trailing_slash = this->request_.request_target() + "/";
            return redirect_to(with_trailing_slash);
        }
        // index ?
        //  Yes -> static
        //  No  -> autoindex?
        //          Yes -> autoindex; indexがなくてもautoindexは表示
        //  -> 404
        if (!has_valid_index_page()) {
            if (is_autoindex()) {
                // return response_autoindex();
                DEBUG_PRINT(YELLOW, "  GET 8 -> autoindex");
                return get_directory_listing(rooted_path, &this->body_buf_);
            }
            DEBUG_PRINT(YELLOW, "  GET 9 err: not found");
            return NotFound;
        }
    }

    DEBUG_PRINT(YELLOW, "  GET 10");
    Result<std::string, StatusCode> indexed = Config::get_indexed_path(this->server_config_,
                                                                       this->request_.request_target());
    if (indexed.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 11 err: indexd path error");
        return indexed.get_err_value();
    }

    const std::string indexed_path = indexed.get_ok_value();
    DEBUG_PRINT(YELLOW, "  GET 12 indexed_path[%s]", indexed_path.c_str());
    Result<bool, StatusCode> is_file = FileHandler::is_file(indexed_path);
    if (is_file.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 13 err: is_file.err");
        return is_file.get_err_value();
    }
    if (!is_file.get_ok_value()) {
        DEBUG_PRINT(YELLOW, "  GET 14 err: not file");
        return BadRequest;
    }
    DEBUG_PRINT(YELLOW, "  GET 15 ok -> file");
    // return response_static(indexed_path);
    return get_file_content(indexed_path, &this->body_buf_);
}
