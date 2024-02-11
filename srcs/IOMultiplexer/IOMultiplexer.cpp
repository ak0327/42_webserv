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

const int TIMEOUT_MS = 2500;

}  // namespace

////////////////////////////////////////////////////////////////////////////////

EPollMultiplexer::EPollMultiplexer(int socket_fd)
	: socket_fd_(socket_fd),
	  epoll_fd_(INIT_FD),
	  ev_(),
	  new_event_() {
	errno = 0;
	this->epoll_fd_ = epoll_create(INIT_SIZE);
	if (this->epoll_fd_ == EPOLL_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] epoll_create:" + err_info);
	}

	this->ev_.data.fd = this->socket_fd_;
	this->ev_.events = EPOLLIN;
	errno = 0;
	if (epoll_ctl(this->epoll_fd_, EPOLL_CTL_ADD, this->socket_fd_, &this->ev_) == -1) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] epoll_ctl:" + err_info);
	}
}

EPollMultiplexer::~EPollMultiplexer() {
	errno = 0;
	if (close(this->epoll_fd_) == CLOSE_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << "[Server Error] close:" << err_info << std::endl;
	}
	this->epoll_fd_ = INIT_FD;
}

Result<int, std::string> EPollMultiplexer::get_io_ready_fd() {
	int ready_fd_count;

	errno = 0;
	ready_fd_count = epoll_wait(this->epoll_fd_, &this->new_event_, 1, TIMEOUT_MS);
	if (ready_fd_count == -1) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}
	if (this->new_event_.events & EPOLLERR) {
		std::string err_info = create_error_info("I/O Error occurred", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}
	if (ready_fd_count == EPOLL_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}
	return Result<int, std::string>::ok(this->new_event_.data.fd);
}

Result<int, std::string> EPollMultiplexer::register_connect_fd(int connect_fd) {
	this->ev_.events = EPOLLIN;
	this->ev_.data.fd = connect_fd;
	errno = 0;
	if (epoll_ctl(this->epoll_fd_, EPOLL_CTL_ADD, connect_fd, &this->ev_) == EPOLL_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> EPollMultiplexer::clear_fd(int clear_fd) {
	errno = 0;
	if (epoll_ctl(this->epoll_fd_, EPOLL_CTL_DEL, clear_fd, NULL) == EPOLL_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

namespace {

const int KQUEUE_ERROR = -1;
const int KEVENT_ERROR = -1;

const int EVENT_COUNT = 1;
const int KEVENT_TIMEOUT = 0;
const int INIT_KQ = -1;

Result<int, std::string> init_kqueue() {
	int kq;

	errno = 0;
	kq = kqueue();
	if (kq == KQUEUE_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(kq);
}

Result<int, std::string> kevent_register(int kq, struct kevent *change_event) {
	errno = 0;
	if (kevent(kq, change_event, EVENT_COUNT, NULL, 0, NULL) == KEVENT_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> kevent_wait(int kq, struct kevent *new_event) {
	int events;
	struct timespec	timeout = {};

	timeout.tv_sec = 2;
	timeout.tv_nsec = 500 * 1000;

	errno = 0;
	events = kevent(kq, NULL, 0, new_event, EVENT_COUNT, &timeout);
	if (events == KEVENT_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(events);
}

Result<int, std::string> cast_fd_uintptr_to_int(uintptr_t ident) {
	if (ident > static_cast<uintptr_t>(INT_MAX)) {
		return Result<int, std::string>::err("invalid fd");
	}
	return Result<int, std::string>::ok(static_cast<int>(ident));
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

KqueueMultiplexer::KqueueMultiplexer(int socket_fd)
	: socket_fd_(socket_fd),
      kq_(INIT_KQ),
      change_event_(),
      new_event_() {
	Result<int, std::string> kq_result, kevent_result;

	DEBUG_SERVER_PRINT("[I/O multiplexer : kqueue]");

	kq_result = init_kqueue();
	if (kq_result.is_err()) {
		std::string err_info = create_error_info(kq_result.get_err_value(), __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] kqueue:" + err_info);
	}
	this->kq_ = kq_result.get_ok_value();

	EV_SET(&this->change_event_, this->socket_fd_, EVFILT_READ, EV_ADD, 0, 0, NULL);
	kevent_result = kevent_register(this->kq_, &this->change_event_);
	if (kevent_result.is_err()) {
		std::string err_info = create_error_info(kevent_result.get_err_value(), __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] kevent:" + err_info);
	}
}

KqueueMultiplexer::~KqueueMultiplexer() {
	// todo: clear all event?
}

Result<int, std::string> KqueueMultiplexer::get_io_ready_fd() {
	Result<int, std::string> kevent_result, cast_result;
	int new_events;

	kevent_result = kevent_wait(this->kq_, &this->new_event_);
	if (kevent_result.is_err()) {
		std::string err_info = create_error_info(kevent_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] kevent:" + err_info);
	}
	new_events = kevent_result.get_ok_value();
	if (new_events == KEVENT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	cast_result = cast_fd_uintptr_to_int(this->new_event_.ident);
	if (cast_result.is_err()) {
		std::string err_info = create_error_info(cast_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error]" + err_info);
	}
	return Result<int, std::string>::ok(cast_result.get_ok_value());
}

Result<int, std::string> KqueueMultiplexer::register_connect_fd(int connect_fd) {
	EV_SET(&this->change_event_, connect_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	return kevent_register(this->kq_, &this->change_event_);
}

Result<int, std::string> KqueueMultiplexer::clear_fd(int clear_fd) {
	Result<int, std::string> kevent_result;
	std::string err_str, err_info;

	EV_SET(&this->change_event_, clear_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	kevent_result = kevent_register(this->kq_, &this->change_event_);
	if (kevent_result.is_err()) {
		err_info = create_error_info(kevent_result.get_err_value(), __FILE__, __LINE__);
		err_str = "kevent:" + err_info;
	}
	errno = 0;
	if (close(clear_fd) == CLOSE_ERROR) {
		if (!err_str.empty()) {
			err_str += " ,";
		}
		err_info = create_error_info(errno, __FILE__, __LINE__);
		err_str += "close:" + err_info;
	}
	if (!err_str.empty()) {
		return Result<int, std::string>::err(err_str);
	}
	return Result<int, std::string>::ok(OK);
}

#else

namespace {

const int SELECT_ERROR = -1;

const int SELECT_TIMEOUT = 0;
const int MAX_SESSION = 128;

fd_set init_fds(int socket_fd, const std::vector<int> &connect_fds) {
	fd_set fds;
	std::vector<int>::const_iterator fd;

	FD_ZERO(&fds);
	FD_SET(socket_fd, &fds);

	for (fd = connect_fds.begin(); fd != connect_fds.end(); ++fd) {
		if (*fd == INIT_FD) {
			continue;
		}
		FD_SET(*fd, &fds);
	}
	return fds;
}

int get_max_fd(const std::vector<int> &connect_fds, int socket_fd) {
	int max_fd;

	max_fd = *std::max_element(connect_fds.begin(), connect_fds.end());
	return std::max(max_fd, socket_fd);
}

Result<int, std::string> select_fds(int max_fd, fd_set *fds) {
	struct timeval timeout = {};
	int select_ret;

	// timeout < 1.5sec, communicate error ??
	timeout.tv_sec = 2;
	timeout.tv_usec = 500 * 1000;  // 500ms

	errno = 0;
	select_ret = select(max_fd + 1, fds, NULL, NULL, &timeout);
	if (select_ret == SELECT_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(select_ret);
}

Result<int, int> get_ready_fd(const std::vector<int> &connect_fds,
							  fd_set *fds, int socket_fd) {
	std::vector<int>::const_iterator fd;

	if (FD_ISSET(socket_fd, fds)) {
		return Result<int, int>::ok(socket_fd);
	}

	for (fd = connect_fds.begin(); fd != connect_fds.end(); ++fd) {
		if (*fd == INIT_FD) {
			continue;
		}
		if (!FD_ISSET(*fd, fds)) {
			continue;
		}
		return Result<int, int>::ok(*fd);
	}
	return Result<int, int>::err(ERR);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

SelectMultiplexer::SelectMultiplexer(int socket_fd) {
	DEBUG_SERVER_PRINT("[I/O multiplexer : select]");

	this->socket_fd_ = socket_fd;
	this->connect_fds_ = std::vector<int>(MAX_SESSION, INIT_FD);
	this->fds_ = init_fds(this->socket_fd_, this->connect_fds_);
}

SelectMultiplexer::~SelectMultiplexer() {
	for (int i = 0; i < MAX_SESSION; ++i) {
		if (this->connect_fds_[i] == INIT_FD) {
			continue;
		}
		errno = 0;
		if (close(this->connect_fds_[i]) == CLOSE_ERROR) {
			std::string err_info = create_error_info(errno, __FILE__, __LINE__);
			std::cerr << "[Error] close:" << err_info << std::endl;
		}
		this->connect_fds_[i] = INIT_FD;
	}
}

Result<int, std::string> SelectMultiplexer::get_io_ready_fd() {
	int max_fd;
	Result<int, std::string> select_result;
	Result<int, int> fd_result;

	this->fds_ = init_fds(this->socket_fd_, this->connect_fds_);
	max_fd = get_max_fd(this->connect_fds_, this->socket_fd_);
	select_result = select_fds(max_fd, &this->fds_);
	if (select_result.is_err()) {
		std::string err_info = create_error_info(select_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] select:" + err_info);
	}
	if (select_result.get_ok_value() == SELECT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	fd_result = get_ready_fd(this->connect_fds_, &this->fds_, this->socket_fd_);
	if (fd_result.is_err()) {
		std::string err_info = create_error_info("ready fd not found", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] " + err_info);
	}
	return Result<int, std::string>::ok(fd_result.get_ok_value());
}

Result<int, std::string> SelectMultiplexer::clear_fd(int clear_fd) {
	std::vector<int>::iterator fd = std::find(this->connect_fds_.begin(),
											  this->connect_fds_.end(),
											  clear_fd);
	if (fd == this->connect_fds_.end()) {
		std::string err_info = create_error_info("clear fd not found", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] " + err_info);
	}

	FD_CLR(*fd, &this->fds_);
	errno = 0;
	if (close(*fd) == CLOSE_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("close:" + err_info);
	}
	*fd = INIT_FD;
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> SelectMultiplexer::register_connect_fd(int connect_fd) {
	std::vector<int>::iterator fd = std::find(this->connect_fds_.begin(),
											  this->connect_fds_.end(),
											  INIT_FD);
	if (fd == this->connect_fds_.end()) {
		std::string err_info = create_error_info("over max connection", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Info] " + err_info);
	}
	*fd = connect_fd;
	return Result<int, std::string>::ok(OK);
}

#endif
