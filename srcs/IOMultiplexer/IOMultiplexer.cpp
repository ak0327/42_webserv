#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <climits>
#include <string>
#include <vector>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Server.hpp"


namespace {

const int SELECT_ERROR = -1;
const int SELECT_TIMEOUT = 0;

}  // namespace


Select::Select()
    : read_fds_(),
      write_fds_(),
      queue_(),
      read_fd_set_(),
      write_fd_set_(),
      max_fd_(0) {
	DEBUG_SERVER_PRINT("[I/O multiplexer : select]");
    FD_ZERO(&this->read_fd_set_);
    FD_ZERO(&this->write_fd_set_);

    this->timeout_.tv_sec = 0;
    this->timeout_.tv_usec = 0;
}


Select::~Select() {
    for (std::set<int>::iterator fd = this->read_fds_.begin(); fd != this->read_fds_.end(); ++fd) {
        FD_CLR(*fd, &this->read_fd_set_);
    }
    for (std::set<int>::iterator fd = this->write_fds_.begin(); fd != this->write_fds_.end(); ++fd) {
        FD_CLR(*fd, &this->write_fd_set_);
    }
    this->read_fds_.clear();
    this->write_fds_.clear();
    this->queue_.clear();
}


void Select::init_fds() {
    FD_ZERO(&this->read_fd_set_);
    FD_ZERO(&this->write_fd_set_);

    for (std::set<int>::iterator fd = this->read_fds_.begin(); fd != this->read_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        FD_SET(*fd, &this->read_fd_set_);
    }
    for (std::set<int>::iterator fd = this->write_fds_.begin(); fd != this->write_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        FD_SET(*fd, &this->write_fd_set_);
    }
}


bool is_setting_no_timeout(struct timeval timeout) {
    return timeout.tv_sec < 0
            || timeout.tv_usec < 0
            || (timeout.tv_sec <= 0 && timeout.tv_usec <= 0);
}


Result<int, std::string> Select::select_fds() {
    std::ostringstream oss_read_fds;
    oss_read_fds << "read_fds: [";
    for (std::set<int>::iterator fd = this->read_fds_.begin(); fd != this->read_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        oss_read_fds << *fd << " ";
    }
    oss_read_fds << "]";
    std::ostringstream oss_write_fds;
    oss_write_fds << "write_fds: [";
    for (std::set<int>::iterator fd = this->write_fds_.begin(); fd != this->write_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        oss_write_fds << *fd << " ";
    }
    oss_write_fds << "]";
    DEBUG_PRINT(CYAN, "select check fds:");
    DEBUG_PRINT(CYAN, " %s", oss_read_fds.str().c_str());
    DEBUG_PRINT(CYAN, " %s", oss_write_fds.str().c_str());

    init_fds();
    this->max_fd_ = get_max_fd();

    errno = 0;
    int select_ret;
    if (is_setting_no_timeout(this->timeout_)) {
        DEBUG_PRINT(CYAN, "select: timeout NULL");
        select_ret = select(this->max_fd_ + 1, &this->read_fd_set_, &this->write_fd_set_, NULL, NULL);
    } else {
        DEBUG_PRINT(CYAN, "select: timeout %.2f sec", this->timeout_.tv_sec + this->timeout_.tv_usec / 1000000.f);
        select_ret = select(this->max_fd_ + 1, &this->read_fd_set_, &this->write_fd_set_, NULL, &this->timeout_);
    }
    // int select_ret = select(this->max_fd_ + 1, &this->fd_set_, NULL, NULL, NULL);
    if (select_ret == SELECT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(select_ret);
}


int Select::get_ready_fd() {
    std::ostringstream oss_read_fds;
    oss_read_fds << "ready read_fds: [";
    for (std::set<int>::iterator fd = this->read_fds_.begin(); fd != this->read_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        if (!FD_ISSET(*fd, &this->read_fd_set_)) { continue; }
        oss_read_fds << *fd << " ";
    }
    oss_read_fds << "]";
    std::ostringstream oss_write_fds;
    oss_write_fds << "ready write_fds: [";
    for (std::set<int>::iterator fd = this->write_fds_.begin(); fd != this->write_fds_.end(); ++fd) {
        if (*fd == INIT_FD) { continue; }
        if (!FD_ISSET(*fd, &this->write_fd_set_)) { continue; }
        oss_write_fds << *fd << " ";
    }
    oss_write_fds << "]";
    std::ostringstream oss_queue;
    oss_queue << "queue: [";
    for (std::deque<int>::iterator fd = this->queue_.begin(); fd != this->queue_.end(); ++fd) {
        oss_queue << *fd << " ";
    }
    oss_queue << "], size:" << this->queue_.size();
    DEBUG_PRINT(YELLOW, "%s", oss_read_fds.str().c_str());
    DEBUG_PRINT(YELLOW, "%s", oss_write_fds.str().c_str());
    DEBUG_PRINT(YELLOW, "%s", oss_queue.str().c_str());


    int ready_fd = INIT_FD;
    for (std::deque<int>::iterator fd = this->queue_.begin(); fd != this->queue_.end(); ++fd) {
        if (FD_ISSET(*fd, &this->read_fd_set_)) {
            ready_fd = *fd;
            this->queue_.erase(fd);
            this->queue_.push_back(ready_fd);
            break;
        }
        if (FD_ISSET(*fd, &this->write_fd_set_)) {
            ready_fd = *fd;
            this->queue_.erase(fd);
            this->queue_.push_back(ready_fd);
            break;
        }
    }
    return ready_fd;
}



int Select::get_max_fd() const {
    int max_fd = INIT_FD;

    if (!this->read_fds_.empty()) {
        max_fd = *std::max_element(this->read_fds_.begin(), this->read_fds_.end());
    }
    if (!this->write_fds_.empty()) {
        max_fd = *std::max_element(this->write_fds_.begin(), this->write_fds_.end());
    }
    return max_fd;
}


Result<int, std::string> Select::get_io_ready_fd() {
    this->max_fd_ = get_max_fd();
	init_fds();

    Result<int, std::string> select_result = select_fds();
	if (select_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(select_result.err_value());
		return Result<int, std::string>::err("[Server Error] select:" + err_info);
	}
	if (select_result.ok_value() == SELECT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	int ready_fd = get_ready_fd();
    DEBUG_SERVER_PRINT(" get_ready_fd -> ready_fd: %d", ready_fd);
    return Result<int, std::string>::ok(ready_fd);
}


void clear_queue(int fd, std::deque<int> *queue) {
    for (std::deque<int>::iterator itr = queue->begin(); itr != queue->end(); ++itr) {
        if (*itr == fd) {
            queue->erase(itr);
            return;
        }
    }
}


Result<int, std::string> Select::clear_fd(int clear_fd) {
	std::set<int>::iterator fd;
    // std::cout << CYAN << "clear_fd: " << clear_fd << RESET << std::endl;

    fd  = std::find(this->read_fds_.begin(), this->read_fds_.end(), clear_fd);
	if (fd != this->read_fds_.end()) {
        FD_CLR(*fd, &this->read_fd_set_);
        this->read_fds_.erase(fd);
        // std::cout << CYAN << "read_fd erase: " << *fd << RESET << std::endl;

        clear_queue(clear_fd, &this->queue_);
        return Result<int, std::string>::ok(OK);
	}

    fd  = std::find(this->write_fds_.begin(), this->write_fds_.end(), clear_fd);
    if (fd != this->write_fds_.end()) {
        FD_CLR(*fd, &this->write_fd_set_);
        this->write_fds_.erase(fd);
        // std::cout << CYAN << "write_fd erase: " << *fd << RESET << std::endl;

        clear_queue(clear_fd, &this->queue_);
        return Result<int, std::string>::ok(OK);
    }

    std::string err_info = CREATE_ERROR_INFO_STR("clear read_fd not found");
    return Result<int, std::string>::err("[Server Error] " + err_info);
}


Result<int, std::string> Select::register_read_fd(int read_fd) {
    if (FD_ISSET(read_fd, &this->read_fd_set_)) {
        std::string err_info = CREATE_ERROR_INFO_STR("read_fd already registered");
        DEBUG_PRINT(WHITE, "%s", err_info.c_str());
        // return Result<int, std::string>::err(err_info);
        return Result<int, std::string>::ok(OK);
    }

    this->read_fds_.insert(read_fd);
    FD_SET(read_fd, &this->read_fd_set_);
    this->max_fd_ = std::max(this->max_fd_, read_fd);

    this->queue_.push_back(read_fd);
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Select::register_write_fd(int write_fd) {
    if (FD_ISSET(write_fd, &this->write_fd_set_)) {
        std::string err_info = CREATE_ERROR_INFO_STR("write_fd already registered");
        DEBUG_PRINT(WHITE, "%s", err_info.c_str());
        // return Result<int, std::string>::err(err_info);
        return Result<int, std::string>::ok(OK);
    }

    this->write_fds_.insert(write_fd);
    FD_SET(write_fd, &this->write_fd_set_);
    this->max_fd_ = std::max(this->max_fd_, write_fd);

    this->queue_.push_back(write_fd);
    return Result<int, std::string>::ok(OK);
}


FdType Select::get_fd_type(int fd) {
    std::set<int>::const_iterator itr;

    itr = std::find(this->read_fds_.begin(), this->read_fds_.end(), fd);
    if (itr != this->read_fds_.end()) {
        return kReadFd;
    }
    itr = std::find(this->write_fds_.begin(), this->write_fds_.end(), fd);
    if (itr != this->write_fds_.end()) {
        return kWriteFd;
    }
    return kFdError;
}


void Select::set_io_timeout(int timeout_msec) {
    if (timeout_msec <= 0) {
        DEBUG_PRINT(CYAN, "select set_io_timeout: [%.2f]->[-]sec",
                    this->timeout_.tv_sec + this->timeout_.tv_usec/1000000.f);
        this->timeout_.tv_sec = 0;
        this->timeout_.tv_usec = 0;
    } else {
        DEBUG_PRINT(CYAN, "select set_io_timeout: [%.2f]->[%.2f]sec",
                    this->timeout_.tv_sec + this->timeout_.tv_usec/1000000.f, timeout_msec/1000.f);
        this->timeout_.tv_sec = timeout_msec / 1000;
        this->timeout_.tv_usec = timeout_msec % 1000 * 1000;
    }
}
