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
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"


bool HttpResponse::is_cgi_file() const {
    Result<bool, int> result = Config::is_cgi_mode_on(this->server_config_,
                                                      this->request_.target());
    if (result.is_err()) {
        return false;
    }
    bool cgi_mode = result.ok_value();
    if (!cgi_mode) {
        return false;
    }
    return Config::is_cgi_extension(this->server_config_,
                                    this->request_.target());
}


bool HttpResponse::is_redirect() const {
    Result<bool, int> result = Config::is_redirect(this->server_config_,
                                                   this->request_.target());
    return result.is_ok() && result.ok_value();
}


StatusCode HttpResponse::get_redirect_content(const ReturnDirective &redirect) {
    DEBUG_PRINT(RED, "redirect.text: %s (L:%d)", redirect.text.c_str(), __LINE__);
    std::string redirect_path;
    if (HttpMessageParser::is_absolute_uri(redirect.text)) {
        DEBUG_PRINT(RED, "external redirect", __LINE__);
        // external redirect
        redirect_path = redirect.text;
    } else {
        DEBUG_PRINT(RED, "local redirect", __LINE__);
        Result<HostPortPair, StatusCode> info_result = this->request_.server_info();
        if (info_result.is_err()) {
            return info_result.err_value();
        }
        // local redirect
        HostPortPair server_info = info_result.ok_value();
        redirect_path = "http://";

        redirect_path.append(server_info.first);
        redirect_path.append(":");
        if (!server_info.second.empty()) {
            redirect_path.append(server_info.second);
        } else {
            redirect_path.append(this->server_listen_.first);
        }
        redirect_path.append(redirect.text);
    }
    this->headers_[LOCATION] = redirect_path;
    return redirect.code;
}


bool HttpResponse::has_valid_index_page() const {
    Result<std::string, StatusCode> indexed;
    indexed = Config::get_indexed_path(this->server_config_,
                                       this->request_.target());
    return indexed.is_ok();
}


bool HttpResponse::is_method_available() const {
    // Result<bool, int> allowed;
    // allowed = Config::is_method_allowed(this->server_config_,
    //                                     this->request_.target(),
    //                                     this->request_.method());
    // return allowed.is_ok() && allowed.ok_value();
    return Config::is_method_allowed(this->server_config_,
                                    this->request_.target(),
                                    this->client_listen_,
                                    this->request_.method());
}


bool HttpResponse::is_autoindex() const {
    Result<bool, int> is_autoindex;
    is_autoindex = Config::is_autoindex_on(this->server_config_,
                                           this->request_.target());
    return is_autoindex.is_ok() && is_autoindex.ok_value();
}


bool HttpResponse::is_redirect_target() const {
    Result<bool, int> is_redirect;
    is_redirect = Config::is_redirect(this->server_config_,
                                      this->request_.target());
    return is_redirect.is_ok() && is_redirect.ok_value();
}


StatusCode HttpResponse::redirect_to(const std::string &move_to) {
    ReturnDirective redirect;
    redirect.return_on = true;
    redirect.code = MovedPermanently;
    redirect.text = move_to;
    return get_redirect_content(redirect);
}


std::string HttpResponse::get_http_date() {
    time_t gmt_time;

    std::time(&gmt_time);
    return get_http_date(gmt_time);
}


std::string HttpResponse::get_http_date(time_t time) {
    char date[1024];
    // IMF-fixdate "%a, %d %b %Y %H:%M:%S GMT"
    std::strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&time));
    return std::string(date);
}


std::string HttpResponse::get_http_date_jst(time_t time) {
    time_t UTC_TO_JST_OFFSET = 9 * 60 * 60;
    time_t jst_time = time + UTC_TO_JST_OFFSET;

    char date[1024];
    std::strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S JST", std::gmtime(&jst_time));
    return std::string(date);
}


// static
//   file      -> error / redirect / response
//   directory -> error / redirect / autoindex
// dynamic
//   cgi       -> error / response ; already branched out
//   api       -> error / response
StatusCode HttpResponse::get_request_body() {
    DEBUG_PRINT(YELLOW, "  GET 1 taget[%s]", this->request_.target().c_str());
    if (!is_method_available()) {
        DEBUG_PRINT(YELLOW, "  GET 2 err: 405");
        return MethodNotAllowed;
    }

    if (is_redirect_target()) {
        // return response_redirect();
        ReturnDirective redirect = Config::get_return(this->server_config_,
                                                      this->request_.target());
        DEBUG_PRINT(YELLOW, "  GET 3 -> redirect");
        return get_redirect_content(redirect);
    }

    // dynamic?
    //  Yes -> dynamic
    if (is_dynamic_endpoint()) {
        DEBUG_PRINT(YELLOW, "  GET 4 -> dynamic");
        return response_dynamic();
    }

    const std::string rooted_path = get_rooted_path();
    DEBUG_PRINT(YELLOW, "  GET 5 rooted_path[%s]", rooted_path.c_str());
    Result<bool, StatusCode> is_directory = FileHandler::is_directory(rooted_path);
    if (is_directory.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 6 err: directory");
        return is_directory.err_value();
    }
    if (is_directory.ok_value()) {
        DEBUG_PRINT(YELLOW, "  GET 7");
        const std::string &directory_path = rooted_path;
        if (!StringHandler::has_trailing_slash(directory_path)) {
            //  No -> 301
            DEBUG_PRINT(YELLOW, "  GET 8 -> redirect + /");
            const std::string with_trailing_slash =
                    this->request_.target() + "/";
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
                                                                       this->request_.target());
    if (indexed.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 11 err: indexd path error");
        return indexed.err_value();
    }

    const std::string indexed_path = indexed.ok_value();
    DEBUG_PRINT(YELLOW, "  GET 12 indexed_path[%s]", indexed_path.c_str());
    Result<bool, StatusCode> is_file = FileHandler::is_file(indexed_path);
    if (is_file.is_err()) {
        DEBUG_PRINT(YELLOW, "  GET 13 err: is_file.err");
        return is_file.err_value();
    }
    if (!is_file.ok_value()) {
        DEBUG_PRINT(YELLOW, "  GET 14 err: not file");
        return BadRequest;
    }
    DEBUG_PRINT(YELLOW, "  GET 15 ok -> file");
    // return response_static(indexed_path);
    return get_file_content(indexed_path, &this->body_buf_);
}
