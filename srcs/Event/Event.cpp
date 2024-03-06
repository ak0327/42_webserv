#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <map>
#include <utility>
#include "Event.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


Event::Event(int socket_fd,
             int client_fd,
             const AddressPortPair &client_listen,
             const Config &config,
             std::map<std::string, Session> *sessions,
             bool echo_mode_on = false)
    : socket_fd_(socket_fd),
      client_fd_(client_fd),
      config_(config),
      server_info_(),
      server_config_(),
      event_state_(kEventInit),
      request_(NULL),
      response_(NULL),
      request_max_body_size_(ConfigInitValue::kDefaultBodySize),
      client_listen_(client_listen),
      sessions_(sessions),
      echo_mode_on_(echo_mode_on) {}


Event::~Event() {
    close_client_fd();
    clear_request();
    clear_response();
}


void Event::clear_request() {
    if (this->request_) {
        delete this->request_;
        this->request_ = NULL;
    }
}


void Event::clear_response() {
    if (this->response_) {
        delete this->response_;
        this->response_ = NULL;
    }
}


void Event::close_client_fd() {
    if (this->client_fd_ != INIT_FD) {
        shutdown(this->client_fd_, SHUT_RDWR);
        close(this->client_fd_);
        this->client_fd_ = INIT_FD;
    }
}


void Event::kill_cgi_process() {
    if (this->response_) {
        this->response_->kill_cgi_process();
    }
}


// todo: unused??
void Event::clear_cgi() {
    if (this->response_) {
        this->response_->clear_cgi();
    }
}


time_t Event::cgi_timeout_limit() const {
    return this->response_ ? this->response_->cgi_timeout_limit() : 0;
}


// -----------------------------------------------------------------------------


int Event::cgi_read_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->cgi_read_fd();
}


int Event::cgi_write_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->cgi_write_fd();
}


int Event::client_fd() const {
    return this->client_fd_;
}


EventPhase Event::event_phase() const {
    return this->event_state_;
}


std::string Event::event_phase_str(const EventPhase &phase) {
    return std::string(event_phase_char(phase));
}


const char *Event::event_phase_char() {
    return event_phase_char(this->event_phase());
}


const char *Event::event_phase_char(const EventPhase &phase) {
    switch (phase) {
        case kEventInit:                return "kEventInit";
        case kReceivingRequest:         return "kReceivingRequest";
        case kParsingRequest:           return "kParsingRequest";
        case kReceivingBody:            return "kReceivingBody";
        case kReadingRequest:           return "kReadingRequest";
        case kExecutingMethod:          return "kExecutingMethod";
        case kCreatingResponseBody:     return "kCreatingResponseBody";
        case kCreatingCGIBody:          return "kCreatingCGIBody";
        case kReadingFile:              return "kReadingFile";
        case kExecuteCGI:               return "kExecuteCGI";
        case kSendingRequestBodyToCgi:  return "kSendingRequestBodyToCgi";
        case kReceivingCgiResponse:     return "kReceivingCgiResponse";
        case kSendingResponse:          return "kSendingResponse";
        case kEventCompleted:           return "kEventCompleted";
        case kEventError:               return "kEventError";
        default:                        return "UnknownEvent";
    }
}


void Event::set_event_phase(const EventPhase &set_phase) {
    DEBUG_PRINT(WHITE, "set_event_phase [%s]->[%s]",
                event_phase_char(this->event_state_),
                event_phase_char(set_phase));
    this->event_state_ = set_phase;
}


bool Event::is_event_phase_expect(const EventPhase &expect) const {
    return this->event_state_ == expect;
}


bool Event::is_continue_recv(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == Continue;
}


bool Event::is_continue_recv(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == Continue;
}


bool Event::is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == PrepareNextProc;
}


bool Event::is_executing_cgi(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == ExecutingCgi;
}


bool Event::is_executing_cgi(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == ExecutingCgi;
}


bool Event::is_connection_closed(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == ConnectionClosed;
}


bool Event::is_keepalive() const {
    if (this->echo_mode_on_) {
        return false;
    }
    if (!this->request_ || this->request_->is_client_connection_close()) {
        return false;
    }
    const int KEEPALIVE_TIMEOUT_INFINITY = 0;
    return this->config_.keepalive_timeout() != KEEPALIVE_TIMEOUT_INFINITY;
}


std::ostringstream &operator<<(std::ostringstream &out, const Event &event) {
    out << "[Event]: ";
    out << "phase: " << Event::event_phase_str(event.event_phase()) << ", ";
    out << "client_fd: " << event.client_fd() << ", ";
    out << "cgi_read_fd: " << event.cgi_read_fd() << ", ";
    out << "cgi_write_fd: " << event.cgi_write_fd();
    return out;
}
