#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <iostream>
#include <set>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Server.hpp"


void Server::management_timeout_events() {
    time_t current_time = std::time(NULL);
    DEBUG_PRINT(GREEN, "[management_timeout_event] current time: %zu", current_time);

    management_cgi_executing_timeout(current_time);
    management_active_client_timeout(current_time);
    management_idling_client_timeout(current_time);
}


void Server::erase_from_timeout_manager(int cgi_fd) {
    std::set<FdTimeoutLimitPair>::iterator itr;
    for (itr = this->cgi_fds_.begin(); itr != this->cgi_fds_.end(); ++itr) {
        int fd = itr->second;
        if (cgi_fd == fd) {
            this->cgi_fds_.erase(itr);
            return;
        }
    }
}


void Server::management_cgi_executing_timeout(time_t current_time) {
    std::ostringstream cgi_sessions;
    cgi_sessions << " cgi_sessions:[";
    for (std::map<CgiFd, Event *>::iterator itr = cgi_events_.begin(); itr != cgi_events_.end(); ++itr) {
        cgi_sessions << "fd:" << itr->first << ", client:" << itr->second << " ";
    }
    cgi_sessions << "]";
    DEBUG_PRINT(GREEN, "%s", cgi_sessions.str().c_str());

    std::ostringstream cgi_fds;
    cgi_fds << " cgi_fds:[";
    for (std::set<FdTimeoutLimitPair>::iterator itr = this->cgi_fds_.begin(); itr != this->cgi_fds_.end(); ++itr) {
        cgi_fds << itr->second << " ";
    }
    cgi_fds << "]";
    DEBUG_PRINT(GREEN, "%s", cgi_fds.str().c_str());

    std::set<FdTimeoutLimitPair>::const_iterator cgi;
    for (cgi = this->cgi_fds_.begin(); cgi != this->cgi_fds_.end(); ++cgi) {
        time_t timeout_limit = cgi->first;
        DEBUG_PRINT(GRAY_BACK, " cgi_fd: %d, time limit: %zu, current: %zu -> remain %zu sec",
                    cgi->second, timeout_limit, current_time, (timeout_limit <= current_time ? 0 : timeout_limit - current_time));
        if (current_time < timeout_limit) {
            break;  // sorted
        }

        int cgi_fd = cgi->second;
        Event *client = this->cgi_events_[cgi_fd];
        client->kill_cgi_process();
        DEBUG_PRINT(RED, " cgi killed by signal read:%d, write:%d", client->cgi_read_fd(), client->cgi_write_fd());
    }
    // not erase timeout cgi from cgi_fd; erased after recv cgi result
}


void Server::management_active_client_timeout(time_t current_time) {
    // DEBUG_PRINT(GREEN, " [management] active_clients:");
    // for (std::set<FdTimeoutLimitPair>::iterator itr = this->active_client_time_manager_.begin();
    //     itr != this->active_client_time_manager_.end(); ++itr) {
    //     time_t timeout_limit = itr->first;
    //     DEBUG_PRINT(GREEN, " fd: %d, time limit: %zu, current: %zu -> %s",
    //                 itr->second, timeout_limit, current_time, (timeout_limit <= current_time ? "timeout" : "ok"));
    // }
    std::set<FdTimeoutLimitPair>::iterator itr = this->active_client_time_manager_.begin();
    while (itr != this->active_client_time_manager_.end()) {
        time_t timeout_limit = itr->first;
        DEBUG_PRINT(GRAY_BACK, " [management] active_client: fd: %d, time limit: %zu, current: %zu -> remain %zu sed",
                           itr->second, timeout_limit, current_time, (timeout_limit <= current_time ? 0 : timeout_limit - current_time));
        if (current_time < timeout_limit) {
            break;  // sorted
        }

        int client_fd = itr->second;
        std::map<ClientFd, Event *>::iterator timeout_event = this->client_events_.find(client_fd);
        if (timeout_event == this->client_events_.end())  {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: fd not found in client_events");
            DEBUG_PRINT(RED, "%s", error_msg.c_str());
            ++itr;
            continue;
        }
        Event *client_event = timeout_event->second;
        if (!client_event) {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: client_event null");
            DEBUG_PRINT(RED, "%s, fd: %d", error_msg.c_str(), client_fd);
            continue;
        }

        std::set<FdTimeoutLimitPair>::iterator current = itr;
        ++itr;

        this->active_client_time_manager_.erase(current);

        // client_event->set_to_timeout();
        delete_event(timeout_event);  // client can not recv 408 -> delete
    }
}


void Server::management_idling_client_timeout(time_t current_time) {
    std::set<FdTimeoutLimitPair>::iterator client = this->idling_client_time_manager_.begin();
    while (client != this->idling_client_time_manager_.end()) {
        time_t timeout_limit = client->first;
        DEBUG_PRINT(GRAY_BACK, " idling_client: fd: %d, time limit: %zu, current: %zu -> remain %zu sec",
                    client->second, timeout_limit, current_time, (timeout_limit <= current_time ? 0 : timeout_limit - current_time));
        if (current_time < timeout_limit) {
            break;  // sorted
        }

        int client_fd = client->second;
        std::map<ClientFd, Event *>::iterator timeout_event = this->client_events_.find(client_fd);
        if (timeout_event == this->client_events_.end())  {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: fd not found in client_events");
            DEBUG_PRINT(RED, "%s", error_msg.c_str());
            ++client;
            continue;
        }

        std::set<FdTimeoutLimitPair>::iterator current = client;
        ++client;

        this->idling_client_time_manager_.erase(current);

        delete_event(timeout_event);
    }
}


std::set<FdTimeoutLimitPair>::iterator Server::find_fd_in_timeout_pair(int fd, const std::set<FdTimeoutLimitPair> &pair) {
    std::set<FdTimeoutLimitPair>::iterator itr;
    for (itr = pair.begin(); itr != pair.end(); ++itr) {
        if (itr->second == fd) {
            return itr;
        }
    }
    return pair.end();
}


bool Server::is_idling_client(int fd) {
    std::set<FdTimeoutLimitPair>::iterator client = find_fd_in_timeout_pair(fd,
                                                                            this->idling_client_time_manager_);
    return client != this->idling_client_time_manager_.end();
}


void Server::clear_from_keepalive_clients(int fd) {
    std::set<FdTimeoutLimitPair>::iterator client = find_fd_in_timeout_pair(fd,
                                                                            this->idling_client_time_manager_);
    if (client == this->idling_client_time_manager_.end()) {
        return;
    }

    DEBUG_SERVER_PRINT("idling -> active: client_fd %d", fd);
    this->idling_client_time_manager_.erase(client);
}


void Server::set_io_timeout() {
    const int kEchoModeTimeoutMs = 100;
    if (this->echo_mode_on_) {
        this->fds_->set_io_timeout(kEchoModeTimeoutMs);
        return;
    }

    const int kManagemtntTimeoutMs = 1000;
    if (!this->cgi_fds_.empty()
        || !this->active_client_time_manager_.empty()
        || !this->idling_client_time_manager_.empty()) {
        this->fds_->set_io_timeout(kManagemtntTimeoutMs);
        return;
    }

    const int kTimeoutInfinity = 0;
    this->fds_->set_io_timeout(kTimeoutInfinity);
}


void Server::idling_event(Event *event) {
    // select        -> polling; idoling event
    // epoll, kqueus -> event driven; init event
    if (!event) {
        return;
    }
    int client_fd = event->client_fd();
    update_fd_type(client_fd, kWriteFd, kReadFd);
    event->set_event_phase(kEventInit);
    event->clear_request();
    event->clear_response();

    clear_from_active_client_manager(client_fd);

    time_t timeout_limit = std::time(NULL) + this->config_.keepalive_timeout();
    this->idling_client_time_manager_.insert(FdTimeoutLimitPair(timeout_limit, client_fd));

    DEBUG_SERVER_PRINT("[idling_event] add fd %d to idling -> timeout: %zu, remain %zu sec",
                       client_fd, timeout_limit, this->config_.keepalive_timeout());
    DEBUG_SERVER_PRINT("------------------------------------------------------------------------------------------------");
}


bool Server::is_already_managed(int fd) {
    std::set<FdTimeoutLimitPair>::iterator itr;
    itr = find_fd_in_timeout_pair(fd, this->active_client_time_manager_);
    return itr != this->active_client_time_manager_.end();
}

void Server::clear_from_active_client_manager(int fd) {
    std::set<FdTimeoutLimitPair>::iterator client = find_fd_in_timeout_pair(fd, this->active_client_time_manager_);
    if (client == this->active_client_time_manager_.end()) {
        return;
    }

    DEBUG_SERVER_PRINT("[clear from active_client_manager] clear fd %d (%d)", fd, __LINE__);
    this->active_client_time_manager_.erase(client);
}


// timeout:

// send_timeout: return from CreateResponse ->
void Server::handle_active_client_timeout(Event *client_event) {
    if (!client_event) { return; }
    DEBUG_PRINT(WHITE, "[handle_active_client_timeout] (%d)", __LINE__);

    int client_fd = client_event->client_fd();
    switch (client_event->event_phase()) {
        case kEventInit: {
            time_t recv_timeout = this->config_.recv_timeout();
            time_t timeout_limit = std::time(NULL) + recv_timeout;
            FdTimeoutLimitPair pair(timeout_limit, client_fd);
            this->active_client_time_manager_.insert(pair);
            DEBUG_PRINT(WHITE, " [active client timeout] EventInit: set_timeout [recv_timeout] fd: %d, limit: %zu", client_fd, timeout_limit);
            break;
        }
        // recv timeout already registered when kEventInit
        // case kReceivingRequest: {
        //     if (is_already_managed(client_fd)) {
        //         DEBUG_PRINT(RED, " ReceivingRequest: already managed, recv continue fd: %d", client_fd);
        //         break;
        //     }
        //     time_t recv_timeout = this->config_.recv_timeout();
        //     time_t timeout_limit = std::time(NULL) + recv_timeout;
        //     FdTimeoutLimitPair pair( timeout_limit, client_fd);
        //     this->active_client_time_manager_.insert(pair);
        //     DEBUG_PRINT(RED, " ReceivingRequest: set_timeout [recv_timeout] fd: %d, limit: %zu", client_fd, timeout_limit);
        //     break;
        // }

        case kExecutingMethod:
        case kCreatingResponseBody:
        case kCreatingCGIBody:
        case kExecuteCGI:
            // clear timeout for sending response
            if (is_already_managed(client_fd)) {
                DEBUG_PRINT(WHITE, " [active client timeout] CreatingBody: clear timeout fd: %d", client_fd);
                clear_from_active_client_manager(client_fd);
                break;
            }
            DEBUG_PRINT(WHITE, " [active client timeout] CreatingBody: error? : fd not exist time manager, fd: %d", client_fd);
            break;

        case kSendingResponse: {
            // not registrate -> setting timeout
            if (is_already_managed(client_fd)) {
                DEBUG_PRINT(WHITE, " [active client timeout] SendingResponse: already managed, send continue fd: %d", client_fd);
                break;
            }
            time_t send_timeout = this->config_.send_timeout();
            time_t timeout_limit = std::time(NULL) + send_timeout;
            FdTimeoutLimitPair pair(timeout_limit, client_fd);
            this->active_client_time_manager_.insert(pair);
            DEBUG_PRINT(WHITE, " SendingResponse: set_timeout [send_timeout] fd: %d, limit: %zu", client_fd, timeout_limit);
            break;
        }

        case kEventCompleted:
            // clear timeout

        default:
            break;
    }
}



































//
