#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <vector>
#include "webserv.hpp"
#include "Color.hpp"
#include "Config.hpp"
#include "Event.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "FileHandler.hpp"
#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "HttpMessageParser.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


HttpResponse::HttpResponse(const HttpRequest &request,
                           const ServerConfig &server_config,
                           const AddressPortPair &server_listen,
                           const AddressPortPair &client_listen,
                           std::map<std::string, Session> *sessions,
                           time_t keepalive_timeout)
    : request_(request),
      server_config_(server_config),
      server_listen_(server_listen),
      client_listen_(client_listen),
      sessions_(sessions),
      cgi_handler_(),
      dynamic_(),
      status_code_(StatusOk),
      headers_(),
      body_buf_(),
      response_msg_(),
      keepalive_timeout_sec_(keepalive_timeout) {
    StatusCode request_status = this->request_.request_status();
    this->set_status_code(request_status);

    time_t cgi_timeout = Config::get_cgi_timeout(server_config, request.target());
    this->cgi_handler_.set_timeout_duration_sec(cgi_timeout);

    this->body_buf_ = this->request_.body();
}


HttpResponse::~HttpResponse() {}



bool HttpResponse::is_executing_cgi() const {
    return this->cgi_handler_.is_processing();
}


bool is_method_limited(const Method &method, const std::set<Method> &excluded_methods) {
    std::set<Method>::const_iterator itr = excluded_methods.find(method);
    return itr == excluded_methods.end();
}


StatusCode HttpResponse::is_resource_available(const Method &method) const {
    // std::cout << CYAN << "is_resource_available target: " << this->request_.request_target() << RESET << std::endl;
    Result<std::string, StatusCode> indexed_result = Config::get_indexed_path(this->server_config_,
                                                                              this->request_.target());
    if (indexed_result.is_err()) {
        // std::cout << CYAN << " get_index failure: " << indexed_result.get_err_value() << RESET << std::endl;
        return indexed_result.err_value();
    }

    // std::cout << CYAN << " indexed_path: " << indexed_result.get_ok_value() << RESET << std::endl;

    Result<LimitExceptDirective, int> limit_except_result;
    limit_except_result = Config::limit_except(this->server_config_,
                                               this->request_.target());
    if (limit_except_result.is_err()) {
        // std::cout << CYAN << " not found" << RESET << std::endl;
        return NotFound;
    }

    LimitExceptDirective limit_except = limit_except_result.ok_value();
    if (limit_except.limited) {
        if (is_method_limited(method, limit_except.excluded_methods)) {
            // todo: allow, deny -> StatusOk
            // std::cout << CYAN << " method not allowed" << RESET << std::endl;
            return MethodNotAllowed;
        }
    }
    // std::cout << CYAN << " ok" << RESET << std::endl;
    return StatusOk;
}


void HttpResponse::process_method_not_allowed() {
    add_allow_header();
    this->set_status_code(MethodNotAllowed);
}


ProcResult HttpResponse::exec_method() {
    DEBUG_PRINT(YELLOW, " exec_method 1 status(%d)", this->status_code());
    StatusCode status;
    switch (this->request_.method()) {
        case kGET:
            DEBUG_PRINT(YELLOW, " exec_method 5 - GET");
            status = get_request_body();
            break;

        case kPOST:
            DEBUG_PRINT(YELLOW, " exec_method 5 - POST");
            status = post_target();
            break;

        case kDELETE:
            DEBUG_PRINT(YELLOW, " exec_method 5 - DELETE");
            status = delete_target();
            break;

        default:
            DEBUG_PRINT(YELLOW, " exec_method 5 - method err");
            status = MethodNotAllowed;
    }

    this->set_status_code(status);
    DEBUG_PRINT(YELLOW, " exec_method 8 -> next");
    return Success;
}


Result<ProcResult, std::string> HttpResponse::send_http_response(int client_fd) {
    return Socket::send_buf(client_fd, &this->response_msg_);
}


std::string HttpResponse::get_rooted_path() const {
    std::string root;
    Result<std::string, int> root_result = Config::get_root(this->server_config_,
                                                            this->request_.target());
    if (root_result.is_ok()) {
        root = root_result.ok_value();
    }

    std::string path = root + this->request_.target();
    return path;
}


ProcResult HttpResponse::send_request_body_to_cgi() {
    Result<ProcResult, std::string> result = this->cgi_handler_.send_request_body_to_cgi();
    if (result.is_err()) {
        DEBUG_PRINT(BG_YELLOW, "[Error] send to CGI: %s", result.err_value().c_str());
        this->cgi_handler_.close_write_fd();
        StatusCode error_code = InternalServerError;
        this->set_status_code(error_code);
        return Failure;
    }

    if (result.ok_value() == Continue) {
        return Continue;
    }
    this->cgi_handler_.close_write_fd();
    return Success;
}


Result<ProcResult, ErrMsg> HttpResponse::recv_to_buf(int fd) {
    return Socket::recv_to_buf(fd, &this->body_buf_);
}


ProcResult HttpResponse::recv_to_cgi_buf() {
    ProcResult result = this->cgi_handler_.recv_cgi_output();
    if (result == Failure) {
        StatusCode error_code = BadGateway;
        this->set_status_code(error_code);
    }
    if (result == Timeout) {
        StatusCode error_code = GatewayTimeout;
        this->set_status_code(error_code);
    }
    return result;  // Success/Continue/Timeout/Failure
}


const std::vector<unsigned char> &HttpResponse::body_buf() const {
    return this->body_buf_;
}


const std::vector<unsigned char> &HttpResponse::get_response_message() const {
    return this->response_msg_;
}


StatusCode HttpResponse::status_code() const {
    return this->status_code_;
}


void HttpResponse::set_status_to_cgi_timeout() {
    set_status_code(GatewayTimeout);
}


void HttpResponse::set_status_code(const StatusCode &set_status) {
    DEBUG_PRINT(GRAY, "response set_status [%d]->[%d]", this->status_code(), set_status);
    this->status_code_ = set_status;
}


int HttpResponse::cgi_read_fd() const {
    return this->cgi_handler_.read_fd();
}

int HttpResponse::cgi_write_fd() const {
    return this->cgi_handler_.write_fd();
}


time_t HttpResponse::cgi_timeout_limit() const {
    return this->cgi_handler_.timeout_limit();
}


void HttpResponse::kill_cgi_process() {
    this->cgi_handler_.kill_cgi_process();
}


// todo: unused??
void HttpResponse::clear_cgi() {
    this->cgi_handler_.clear_cgi_process();
}


void HttpResponse::create_echo_msg(const std::vector<unsigned char> &recv_msg) {
    this->response_msg_ = recv_msg;
    std::string echo_message = std::string(recv_msg.begin(), recv_msg.end());
    DEBUG_PRINT(GREEN, "    create_echo_msg:[%s]", echo_message.c_str());
}
