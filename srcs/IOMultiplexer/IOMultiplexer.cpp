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

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)

namespace {

const int EPOLL_TIMEOUT = 0;
const int EPOLL_ERROR = -1;

const int INIT_SIZE = 1;

}  // namespace

////////////////////////////////////////////////////////////////////////////////

EPollMultiplexer::EPollMultiplexer()
	: epoll_fd_(INIT_FD),
	  ev_(),
	  new_event_(),
      timeout_(-1) {
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
        this->timeout_ = -1;
    } else {
        this->timeout_ = timeout_msec;
    }
}


#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

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

KqueueMultiplexer::KqueueMultiplexer()
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


KqueueMultiplexer::~KqueueMultiplexer() {
	// todo: clear all event?
}


Result<int, std::string> KqueueMultiplexer::get_io_ready_fd() {
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


Result<int, std::string> KqueueMultiplexer::init_kqueue() {
    int kq;

    errno = 0;
    kq = kqueue();
    if (kq == KQUEUE_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(kq);
}


Result<int, std::string> KqueueMultiplexer::kevent_wait() {
    int events;

    if (this->timeout_.tv_sec <= 0 || this->timeout_.tv_nsec <= 0) {
        events = kevent(this->kq_, NULL, 0, &this->new_event_, EVENT_COUNT, NULL);
    } else {
        events = kevent(this->kq_, NULL, 0, &this->new_event_, EVENT_COUNT, &timeout);
    }
    if (events == KEVENT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(events);
}


Result<int, std::string> KqueueMultiplexer::kevent_register() {
    errno = 0;
    if (kevent(this->kq_, &this->change_event_, EVENT_COUNT, NULL, 0, NULL) == KEVENT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> KqueueMultiplexer::register_fd(int fd) {
	EV_SET(&this->change_event_, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    // EV_SET(&this->change_event_, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);

    Result<int, std::string> kevent_result = kevent_register();
    if (kevent_result.is_err()) {
        std::string err_info = CREATE_ERROR_INFO_STR(kevent_result.get_err_value());
        return Result<int, std::string>::err("[Server Error] kevent: " + err_info);
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> KqueueMultiplexer::clear_fd(int fd) {
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


void KqueueMultiplexer::set_timeout(int timeout_msec) {
    if (timeout_msec <= 0) {
        this->timeout_.tv_sec = -1;
    } else {
        this->timeout_.tv_sec = timeout_msec / 1000;
        this->timeout_.tv_nsec = timeout_msec % 1000 * 1000 * 1000;
    }
}

#else

namespace {

const int SELECT_ERROR = -1;
const int SELECT_TIMEOUT = 0;

}  // namespace

////////////////////////////////////////////////////////////////////////////////

SelectMultiplexer::SelectMultiplexer() {
	DEBUG_SERVER_PRINT("[I/O multiplexer : select]");
    FD_ZERO(&fd_set_);
    this->timeout_.tv_sec = 0;
}


SelectMultiplexer::~SelectMultiplexer() {
	for (std::size_t i = 0; i < this->fds_.size(); ++i) {
        FD_CLR(this->fds_[i], &this->fd_set_);
	}
    this->fds_.clear();
}


void SelectMultiplexer::init_fds() {
    FD_ZERO(&this->fd_set_);
    for (size_t i = 0; i < this->fds_.size(); ++i) {
        if (this->fds_[i] == INIT_FD) {
            continue;
        }
        FD_SET(this->fds_[i], &this->fd_set_);
    }
}


Result<int, std::string> SelectMultiplexer::select_fds() {
    // debug
    std::cout << CYAN << "fds [";
    for (std::size_t i = 0; i < this->fds_.size(); ++i) {
        std::cout << this->fds_[i];
        if (i + 1 < this->fds_.size()) {
            std::cout << ", ";
        }
    }
    std::cout << "]" << RESET << std::endl;

    init_fds();
    this->max_fd_ = get_max_fd();

    errno = 0;
    int select_ret;
    if (this->timeout_.tv_sec <= 0 || this->timeout_.tv_usec <= 0) {
        select_ret = select(this->max_fd_ + 1, &this->fd_set_, NULL, NULL, NULL);
    } else {
        select_ret = select(this->max_fd_ + 1, &this->fd_set_, NULL, NULL, &this->timeout_);
    }
    // int select_ret = select(this->max_fd_ + 1, &this->fd_set_, NULL, NULL, NULL);
    if (select_ret == SELECT_ERROR) {
        return Result<int, std::string>::err(strerror(errno));
    }
    return Result<int, std::string>::ok(select_ret);
}


int SelectMultiplexer::get_ready_fd() const {
    for (std::size_t i = 0; i < this->fds_.size(); ++i) {
        if (this->fds_[i] == INIT_FD) {
            continue;
        }
        if (!FD_ISSET(this->fds_[i], &this->fd_set_)) {
            continue;
        }
        return this->fds_[i];
    }
    return INIT_FD;
}


int SelectMultiplexer::get_max_fd() const {
    int max_fd = INIT_FD;

    if (!this->fds_.empty()) {
        max_fd = *std::max_element(this->fds_.begin(), this->fds_.end());
    }
    return max_fd;
}


Result<int, std::string> SelectMultiplexer::get_io_ready_fd() {
	init_fds();
	this->max_fd_ = get_max_fd();
    Result<int, std::string> select_result = select_fds();
	if (select_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(select_result.get_err_value());
		return Result<int, std::string>::err("[Server Error] select:" + err_info);
	}
	if (select_result.get_ok_value() == SELECT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	int ready_fd = get_ready_fd();
	return Result<int, std::string>::ok(ready_fd);
}


Result<int, std::string> SelectMultiplexer::clear_fd(int clear_fd) {
	std::deque<int>::iterator fd = std::find(this->fds_.begin(),
											 this->fds_.end(),
											 clear_fd);
	if (fd == this->fds_.end()) {
		std::string err_info = CREATE_ERROR_INFO_STR("clear fd not found");
		return Result<int, std::string>::err("[Server Error] " + err_info);
	}

	FD_CLR(*fd, &this->fd_set_);
	this->fds_.erase(fd);
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> SelectMultiplexer::register_fd(int fd) {
    if (FD_ISSET(fd, &this->fd_set_)) {
        std::string err_info = CREATE_ERROR_INFO_STR("fd already registered");
        return Result<int, std::string>::err(err_info);
    }

    this->fds_.push_back(fd);
    FD_SET(fd, &this->fd_set_);
    this->max_fd_ = std::max(this->max_fd_, fd);
    return Result<int, std::string>::ok(OK);
}


void SelectMultiplexer::set_timeout(int timeout_msec) {
    if (timeout_msec <= 0) {
        this->timeout_.tv_sec = 0;
    } else {
        this->timeout_.tv_sec = timeout_msec / 1000;
        this->timeout_.tv_usec = timeout_msec % 1000 * 1000;
    }
}

#endif
