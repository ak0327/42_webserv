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
    DEBUG_PRINT(GREEN, "management_timeout current: %zu", current_time);

    management_cgi_executing_timeout(current_time);
    management_client_keepalive_timeout(current_time);
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
    cgi_sessions << "debug print cgi_sessions:[";
    for (std::map<CgiFd, Event *>::iterator itr = cgi_events_.begin(); itr != cgi_events_.end(); ++itr) {
        cgi_sessions << "fd:" << itr->first << ", client:" << itr->second << " ";
    }
    cgi_sessions << "]";
    DEBUG_PRINT(GREEN, "%s", cgi_sessions.str().c_str());

    std::ostringstream cgi_fds;
    cgi_fds << "debug print cgi_fds:[";
    for (std::set<FdTimeoutLimitPair>::iterator itr = this->cgi_fds_.begin(); itr != this->cgi_fds_.end(); ++itr) {
        cgi_fds << itr->second << " ";
    }
    cgi_fds << "]";
    DEBUG_PRINT(GREEN, "%s", cgi_fds.str().c_str());

    std::set<FdTimeoutLimitPair>::const_iterator cgi;
    for (cgi = this->cgi_fds_.begin(); cgi != this->cgi_fds_.end(); ++cgi) {
        time_t timeout_limit = cgi->first;
        DEBUG_SERVER_PRINT(" cgi_fd: %d, time limit: %zu, current: %zu -> %s",
                           cgi->second, timeout_limit, current_time, (timeout_limit <= current_time ? "limited" : "ok"));
        if (current_time < timeout_limit) {
            break;  // sorted
        }

        int cgi_fd = cgi->second;
        Event *client = this->cgi_events_[cgi_fd];
        DEBUG_PRINT(RED, " timeout(%zu sec) cgi %d -> kill, client: %p", current_time - timeout_limit, cgi_fd, client);
        client->kill_cgi_process();
        DEBUG_PRINT(RED, " cgi killed by signal read:%d, write:%d", client->cgi_read_fd(), client->cgi_write_fd());
    }
    // todo: erase cgi from timeout?
}


void Server::management_client_keepalive_timeout(time_t current_time) {
    std::set<FdTimeoutLimitPair>::iterator client = this->keepalive_clients_.begin();
    while (client != this->keepalive_clients_.end()) {
        time_t timeout_limit = client->first;
        DEBUG_SERVER_PRINT(" client_fd: %d, time limit: %zu, current: %zu -> %s",
                           client->second, timeout_limit, current_time, (timeout_limit <= current_time ? "limited" : "ok"));
        if (current_time < timeout_limit) {
            DEBUG_PRINT(GREEN, " client %d: time remaining(%zu sec)", client->second, current_time - timeout_limit);
            break;  // sorted
        }

        int client_fd = client->second;
        std::map<Fd, Event *>::iterator timeout_event = this->client_events_.find(client_fd);
        if (timeout_event == this->client_events_.end())  {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: fd not found in client_events");
            DEBUG_PRINT(RED, "%s", error_msg.c_str());
            ++client;
            continue;
        }

        std::set<FdTimeoutLimitPair>::iterator current = client;
        ++client;

        this->keepalive_clients_.erase(current);

        delete_event(timeout_event);
        DEBUG_PRINT(RED, " client %d: time remaining(%zu sec) -> deleted", client_fd, current_time - timeout_limit);
    }
}


std::set<FdTimeoutLimitPair>::iterator Server::find_timeout_fd_pair(int fd, const std::set<FdTimeoutLimitPair> &pair) {
    std::set<FdTimeoutLimitPair>::iterator itr;
    for (itr = pair.begin(); itr != pair.end(); ++itr) {
        if (itr->second == fd) {
            return itr;
        }
    }
    return pair.end();
}


bool Server::is_idling_client(int fd) {
    std::set<FdTimeoutLimitPair>::iterator client = find_timeout_fd_pair(fd, this->keepalive_clients_);
    return client != this->keepalive_clients_.end();
}


void Server::clear_from_keepalive_clients(int fd) {
    std::set<FdTimeoutLimitPair>::iterator client = find_timeout_fd_pair(fd, this->keepalive_clients_);
    if (client == this->keepalive_clients_.end()) {
        return;
    }

    DEBUG_SERVER_PRINT("idling -> active: client_fd %d", fd);
    this->keepalive_clients_.erase(client);
}


void Server::set_io_timeout() {
    const int kEchoModeTimeoutMs = 100;
    if (this->echo_mode_on_) {
        this->fds_->set_io_timeout(kEchoModeTimeoutMs);
        return;
    }

    const int kManagemtntTimeoutMs = 500;
    if (!this->cgi_fds_.empty() || !this->keepalive_clients_.empty()) {
        this->fds_->set_io_timeout(kManagemtntTimeoutMs);
        return;
    }

    const int kTimeoutInfinity = 0;
    this->fds_->set_io_timeout(kTimeoutInfinity);
}
