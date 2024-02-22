#include <sys/wait.h>
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
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

namespace {

}  // namespace

////////////////////////////////////////////////////////////////////////////////

HttpResponse::HttpResponse(const HttpRequest &request,
                           const ServerConfig &server_config)
    : request_(request),
      server_config_(server_config),
      cgi_read_fd_(INIT_FD),
      cgi_pid_(INIT_PID),
      media_type_(NULL),
      headers_(),
      body_buf_(),
      response_msg_() {}


HttpResponse::~HttpResponse() {
    clear_cgi();
    clear_media_type();
}


void HttpResponse::clear_cgi() {
    kill_cgi_process();
    close_cgi_fd();
}


void HttpResponse::clear_media_type() {
    if (this->media_type_) {
        delete media_type_;
        this->media_type_ = NULL;
    }
}


void HttpResponse::kill_cgi_process() {
    int process_status;
    if (!is_cgi_processing(&process_status)) {
        return;
    }
    errno = 0;
    if (kill(this->cgi_pid_, SIGKILL) == KILL_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    this->cgi_pid_ = INIT_PID;  // todo: success only?
}


void HttpResponse::close_cgi_fd() {
    if (this->cgi_read_fd_ == INIT_FD) {
        return;
    }
    errno = 0;
    if (close(this->cgi_read_fd_) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    this->cgi_read_fd_ = INIT_FD;  // todo: success only?
}


// todo: 分岐する？get_contentで取得する？
bool HttpResponse::is_response_error_page(const StatusCode &status_code) const {
    // todo
    return status_code == NotFound;
}

bool HttpResponse::is_executing_cgi() const {
    return this->cgi_fd() != INIT_FD;
}


Result<ProcResult, StatusCode> HttpResponse::exec_method(const StatusCode &status_code) {
    StatusCode status = status_code;
    DEBUG_PRINT(YELLOW, " exec_method 1 status(%d)", status);

    if (!is_response_error_page(status)) {
        std::string target_path = HttpResponse::get_resource_path();
        DEBUG_PRINT(YELLOW, " exec_method 2 path: ", target_path.c_str());
        Method method = HttpMessageParser::get_method(this->request_.method());
        DEBUG_PRINT(YELLOW, " exec_method 3 method: ", method);

        switch (method) {
            case kGET:
                DEBUG_PRINT(YELLOW, " exec_method 4 - GET");
                status = get_request_body(target_path);
                break;

            case kPOST:
                DEBUG_PRINT(YELLOW, " exec_method 4 - POST");
                status = post_request_body(target_path);
                break;

            case kDELETE:
                DEBUG_PRINT(YELLOW, " exec_method 4 - DELETE");
                status = delete_request_body(target_path);
                break;

            default:
                DEBUG_PRINT(YELLOW, " exec_method 4 - err");
                status = BadRequest;
        }
    }

    DEBUG_PRINT(YELLOW, " exec_method 5");
    if (is_response_error_page(status)) {  // todo: error page case
        DEBUG_PRINT(YELLOW, "  result->error");
        get_error_page(status);
        DEBUG_PRINT(YELLOW, "  get_error_page ok");
        return Result<ProcResult, StatusCode>::err(status);  // todo: err ? ok?
    }

    DEBUG_PRINT(YELLOW, " exec_method 6");
    if (is_executing_cgi()) {
        std::string debug_body(this->body_buf_.begin(), this->body_buf_.end());
        DEBUG_PRINT(YELLOW, " exec_method body:[%s]", debug_body.c_str());
        return Result<ProcResult, StatusCode>::ok(ExecutingCgi);
    }

    DEBUG_PRINT(YELLOW, " exec_method 7");
    return Result<ProcResult, StatusCode>::ok(Success);
}

/*
 6.2.1. Document Response
 document-response = Content-Type [ Status ] *other-field NL response-body

 The script MUST return a Content-Type header field.
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-2-1--Document-Response

 Content-Type = "Content-Type:" media-type NL
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3-1--Content-Type

 Status         = "Status:" status-code SP reason-phrase NL
 status-code    = "200" | "302" | "400" | "501" | extension-code
 extension-code = 3digit
 reason-phrase  = *TEXT
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3-3--Status

 other-field     = protocol-field | extension-field
 protocol-field  = generic-field
 extension-field = generic-field
 generic-field   = field-name ":" [ field-value ] NL
 field-name      = token
 field-value     = *( field-content | LWSP )
 field-content   = *( token | separator | quoted-string )
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3--Response-Header-Fields

 response-body = *OCTET
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-4--Response-Message-Body

 UNIX
 The newline (NL) sequence is LF; servers should also accept CR LF as a newline.
                                          ^^^^^^
 */
StatusCode HttpResponse::parse_cgi_document_response() {
    StatusCode parse_result = parse_cgi_output();
    return parse_result;
}


/*
 HTTP-message = start-line CRLF
				*( field-line CRLF )
				CRLF
				[ message-body ]
 https://triple-underscore.github.io/http1-ja.html#http.message
 */
Result<ProcResult, StatusCode> HttpResponse::create_response_message(const StatusCode &code) {
    std::string status_line = create_status_line(code) + CRLF;
    std::string field_lines = create_field_lines();
    std::string empty = CRLF;

    this->response_msg_.insert(this->response_msg_.end(), status_line.begin(), status_line.end());
    this->response_msg_.insert(this->response_msg_.end(), field_lines.begin(), field_lines.end());
    this->response_msg_.insert(this->response_msg_.end(), empty.begin(), empty.end());
    this->response_msg_.insert(this->response_msg_.end(), this->body_buf_.begin(), this->body_buf_.end());

    std::string msg(this->response_msg_.begin(), this->response_msg_.end());
    DEBUG_SERVER_PRINT("response_message2:[%s]", msg.c_str());
    return Result<ProcResult, StatusCode>::ok(Success);
}


std::string get_status_reason_phrase(const StatusCode &code) {
    std::map<StatusCode, std::string>::const_iterator itr;
    itr = STATUS_REASON_PHRASES.find(code);
    if (itr == STATUS_REASON_PHRASES.end()) {
        return EMPTY;
    }
    return itr->second;
}


// status-line = HTTP-version SP status-code SP [ reason-phrase ]
std::string HttpResponse::create_status_line(const StatusCode &code) const {
    std::string status_line;

    status_line.append(this->request_.http_version());
    status_line.append(SP);
    status_line.append(StringHandler::to_string(code));
    status_line.append(SP);
    status_line.append(get_status_reason_phrase(code));
    return status_line;
}


// field-line = field-name ":" OWS field-values OWS
std::string HttpResponse::create_field_lines() const {
	std::map<std::string, std::string>::const_iterator itr;
	std::ostringstream response_headers_oss;
	std::string field_name, field_value;

	for (itr = headers_.begin(); itr != headers_.end(); ++itr) {
		field_name = itr->first;
		field_value = itr->second;

		response_headers_oss << field_name << ":" << SP << field_value << CRLF;
	}
	return response_headers_oss.str();
}


std::string HttpResponse::get_resource_path() {
    std::string root;
    Result<std::string, int> root_result = Config::get_root(this->server_config_,
                                                            this->request_.request_target());
    if (root_result.is_ok()) {
        root = root_result.get_ok_value();
    }

    std::string path = root + this->request_.request_target();
    return path;
}


ssize_t HttpResponse::recv_to_buf(int fd) {
    return HttpRequest::recv_to_buf(fd, &this->body_buf_);
}


Result<ProcResult, StatusCode> HttpResponse::recv_cgi_result() {
    ssize_t recv_size = this->recv_to_buf(cgi_fd());
    if (recv_size == RECV_CLOSED) {
        return Result<ProcResult, StatusCode>::ok(ConnectionClosed);
    }
    std::string debug_buf(this->body_buf_.begin(), this->body_buf_.end());
    // DEBUG_PRINT(YELLOW, "     buf:[%s]", debug_buf.c_str());

    int process_exit_status;
    if (this->is_cgi_processing(&process_exit_status)) {
        return Result<ProcResult, StatusCode>::ok(Continue);
    }
    // DEBUG_PRINT(YELLOW, "     process_exit_status: %d", process_exit_status);
    if (process_exit_status != EXIT_SUCCESS) {
        return Result<ProcResult, StatusCode>::err(InternalServerError);
    }
    close_cgi_fd();
    return Result<ProcResult, StatusCode>::ok(Success);
}


bool HttpResponse::is_cgi_processing(int *status) {
    // DEBUG_PRINT(YELLOW, "    is_cgi_processing 1");
    if (this->cgi_pid_ == INIT_PID) {
        // DEBUG_PRINT(YELLOW, "    is_cgi_processing 2");
        return false;
    }
    int child_status;
    errno = 0;
    pid_t wait_result = waitpid(this->cgi_pid_, &child_status, WNOHANG);
    int tmp_err = errno;
    // DEBUG_PRINT(YELLOW, "    wait_result: %d, errno: %d, ECHILD: %d", wait_result, tmp_err, ECHILD);
    if (tmp_err != 0) {
        // DEBUG_PRINT(YELLOW, "    is_cgi_processing 3");
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(tmp_err);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    if (wait_result == PROCESSING || (wait_result == WAIT_ERROR && tmp_err != ECHILD)) {
        // DEBUG_PRINT(YELLOW, "    is_cgi_processing 4");
        return true;
    }

    // DEBUG_PRINT(YELLOW, "    is_cgi_processing 5");
    if (0 < wait_result && status) {
        // DEBUG_PRINT(YELLOW, "    is_cgi_processing 6");
        *status = WEXITSTATUS(child_status);
    }
    // DEBUG_PRINT(YELLOW, "    is_cgi_processing 7");
    this->cgi_pid_ = INIT_PID;
    return false;
}


const std::vector<unsigned char> &HttpResponse::body_buf() const {
    return this->body_buf_;
}


const std::vector<unsigned char> &HttpResponse::get_response_message() const {
    return this->response_msg_;
}


int HttpResponse::cgi_fd() const {
    return this->cgi_read_fd_;
}


pid_t HttpResponse::cgi_pid() const {
    return this->cgi_pid_;
}

bool HttpResponse::is_cgi_response() {
    return this->media_type_;
}


#ifdef ECHO

void HttpResponse::create_echo_msg(const std::vector<unsigned char> &recv_msg) {
    this->response_msg_ = recv_msg;
    std::string echo_message = std::string(recv_msg.begin(), recv_msg.end());
    DEBUG_PRINT(GREEN, "    create_echo_msg:[%s]", echo_message.c_str());
}

#endif
