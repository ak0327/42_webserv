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

#if defined(__linux__) && !defined(USE_SELECT) && !defined(USE_POLL)

namespace {

const int EPOLL_TIMEOUT = 0;
const int EPOLL_ERROR = -1;

const int INIT_SIZE = 1;
const int TIMEOUT_DISABLED = -1;

}  // namespace

////////////////////////////////////////////////////////////////////////////////

EPollMultiplexer::EPollMultiplexer()
	: epoll_fd_(INIT_FD),
	  ev_(),
	  new_event_(),
      timeout_(TIMEOUT_DISABLED) {
    Result<int, std::string> init_result = init_epoll();
    if (init_result.is_err()) {
        throw std::runtime_error(init_result.get_err_value());
    }
}


EPollMultiplexer::~EPollMultiplexer() {
	errno = 0;
	if (close(this->epoll_fd_) == CLOSE_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		std::cerr << "[Server Error] close:" << err_info << std::endl;
	}
	this->epoll_fd_ = INIT_FD;
}


Result<int, std::string> EPollMultiplexer::init_epoll() {
    errno = 0;
    this->epoll_fd_ = epoll_create(INIT_SIZE);
    if (this->epoll_fd_ == EPOLL_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("[Server Error] epoll_create:" + err_info);
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> EPollMultiplexer::get_io_ready_fd() {
	errno = 0;
	int ready_fd_count = epoll_wait(this->epoll_fd_, &this->new_event_, 1, this->timeout_);
	if (ready_fd_count == EPOLL_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}
	if (this->new_event_.events & EPOLLERR) {
		std::string err_info = CREATE_ERROR_INFO_STR("I/O Error occurred");
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}

	if (ready_fd_count == EPOLL_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}
	return Result<int, std::string>::ok(this->new_event_.data.fd);
}


Result<int, std::string> EPollMultiplexer::register_fd(int fd) {
	this->ev_.events = EPOLLIN;
	this->ev_.data.fd = fd;
	errno = 0;
	if (epoll_ctl(this->epoll_fd_, EPOLL_CTL_ADD, fd, &this->ev_) == EPOLL_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> EPollMultiplexer::clear_fd(int fd) {
	errno = 0;
	if (epoll_ctl(this->epoll_fd_, EPOLL_CTL_DEL, fd, NULL) == EPOLL_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


void EPollMultiplexer::set_timeout(int timeout_msec) {
    if (timeout_msec <= 0) {
        this->timeout_ = TIMEOUT_DISABLED;
    } else {
        this->timeout_ = timeout_msec;
    }
}


#elif defined(__APPLE__) && !defined(USE_SELECT) && !defined(USE_POLL)

namespace {

const int KQUEUE_ERROR = -1;
const int KEVENT_ERROR = -1;

const int EVENT_COUNT = 1;
const int KEVENT_TIMEOUT = 0;
const int INIT_KQ = -1;

Result<int, std::string> cast_fd_uintptr_to_int(uintptr_t ident) {
    if (ident > static_cast<uintptr_t>(INT_MAX)) {
        return Result<int, std::string>::err("invalid fd");
    }
    return Result<int, std::string>::ok(static_cast<int>(ident));
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Kqueue::Kqueue()
	: kq_(INIT_KQ),
      change_event_(),
      new_event_() {
	DEBUG_SERVER_PRINT("[I/O multiplexer : kqueue]");

    Result<int, std::string> kq_result = init_kqueue();
	if (kq_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(kq_result.get_err_value());
		throw std::runtime_error("[Server Error] kqueue:" + err_info);
	}
	this->kq_ = kq_result.get_ok_value();
    this->timeout_.tv_sec = 0;
}


Kqueue::~Kqueue() {
	// todo: clear all event?
}


Result<int, std::string> Kqueue::get_io_ready_fd() {
	Result<int, std::string> kevent_result, cast_result;
	int new_events;

	kevent_result = kevent_wait();
	if (kevent_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(kevent_result.get_err_value());
		return Result<int, std::string>::err("[Server Error] kevent: " + err_info);
	}
	new_events = kevent_result.get_ok_value();
	if (new_events == KEVENT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	cast_result = cast_fd_uintptr_to_int(this->new_event_.ident);
	if (cast_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(cast_result.get_err_value());
		return Result<int, std::string>::err("[Server Error]" + err_info);
	}
	return Result<int, std::string>::ok(cast_result.get_ok_value());
}


Result<int, std::string> Kqueue::init_kqueue() {
    int kq;

    errno = 0;
    kq = kqueue();
    if (kq == KQUEUE_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(kq);
}


Result<int, std::string> Kqueue::kevent_wait() {
    int events;

    if (this->timeout_.tv_sec < 0 || this->timeout_.tv_nsec < 0 || (this->timeout_.tv_sec <= 0 && this->timeout_.tv_nsec <= 0)) {
        events = kevent(this->kq_, NULL, 0, &this->new_event_, EVENT_COUNT, NULL);
    } else {
        events = kevent(this->kq_, NULL, 0, &this->new_event_, EVENT_COUNT, &timeout_);
    }
    if (events == KEVENT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(events);
}


Result<int, std::string> Kqueue::kevent_register() {
    errno = 0;
    if (kevent(this->kq_, &this->change_event_, EVENT_COUNT, NULL, 0, NULL) == KEVENT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Kqueue::register_fd(int fd) {
	EV_SET(&this->change_event_, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    // EV_SET(&this->change_event_, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);

    Result<int, std::string> kevent_result = kevent_register();
    if (kevent_result.is_err()) {
        std::string err_info = CREATE_ERROR_INFO_STR(kevent_result.get_err_value());
        return Result<int, std::string>::err("[Server Error] kevent: " + err_info);
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Kqueue::clear_fd(int fd) {
	Result<int, std::string> kevent_result;

	EV_SET(&this->change_event_, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    // EV_SET(&this->change_event_, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

    kevent_result = kevent_register();
	if (kevent_result.is_err()) {
		const std::string err_info = CREATE_ERROR_INFO_STR(kevent_result.get_err_value());
		return Result<int, std::string>::err("kevent: " + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


void Kqueue::set_timeout(int timeout_msec) {
    if (timeout_msec <= 0) {
        this->timeout_.tv_sec = -1;
    } else {
        this->timeout_.tv_sec = timeout_msec / 1000;
        this->timeout_.tv_nsec = timeout_msec % 1000 * 1000 * 1000;
    }
}

#elif defined(USE_SELECT)

namespace {

const int SELECT_ERROR = -1;
const int SELECT_TIMEOUT = 0;

}  // namespace

////////////////////////////////////////////////////////////////////////////////

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
    oss_queue << "]";
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
    DEBUG_SERVER_PRINT(" -> ready_fd: %d", ready_fd);
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

#else

Poll::Poll() {}

Poll::~Poll() {}

Result<int, std::string> Poll::get_io_ready_fd() {
    return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Poll::register_read_fd(int read_fd) {
    (void)read_fd;
    return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Poll::register_write_fd(int write_fd) {
    (void)write_fd;
    return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Poll::clear_fd(int fd) {
    (void)fd;
    return Result<int, std::string>::ok(OK);
}

FdType Poll::get_fd_type(int fd) {
    (void)fd;
    return kReadFd;
}


#endif
