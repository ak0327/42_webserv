#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <climits>
#include <string>
#include <vector>
#include "webserv.hpp"
#include "Color.hpp"
// #include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
// #include "Server.hpp"

const int OK = 0;  // tmp

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)

namespace {
	int INIT_SIZE = 1;
	int EPOLL_TIMEOUT = 0;
	int IO_TIMEOUT = -1;
	int TIMEOUT_MS = 2500;
	int INIT_FD = -1;

	int ERROR = -1;
}

EPollMultiplexer::EPollMultiplexer(int socket_fd) : _socket_fd(socket_fd),
													_epoll_fd(INIT_FD),
													_ev(),
													_new_event() {
	errno = 0;
	this->_epoll_fd = epoll_create(INIT_SIZE);
	if (this->_epoll_fd == ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] epoll_create:" + err_info);
	}

	this->_ev.data.fd = this->_socket_fd;
	this->_ev.events = EPOLLIN;
	errno = 0;
	if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_ADD, this->_socket_fd, &this->_ev) == -1) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] epoll_ctl:" + err_info);
	}
}

EPollMultiplexer::~EPollMultiplexer() {
	errno = 0;
	if (close(this->_epoll_fd) == ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << "[Server Error] close:" << err_info << std::endl;
	}
	this->_epoll_fd = INIT_FD;
}

Result<int, std::string> EPollMultiplexer::get_io_ready_fd() {
	int ready_fd_count;

	errno = 0;
	ready_fd_count = epoll_wait(this->_epoll_fd, &this->_new_event, 1, TIMEOUT_MS);
	if (ready_fd_count == -1) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}
	if (this->_new_event.events & EPOLLERR) {
		std::string err_info = create_error_info("I/O Error occurred", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_wait:" + err_info);
	}
	if (ready_fd_count == EPOLL_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}
	return Result<int, std::string>::ok(this->_new_event.data.fd);
}

Result<int, std::string> EPollMultiplexer::register_connect_fd(int connect_fd) {
	this->_ev.events = EPOLLIN;
	this->_ev.data.fd = connect_fd;
	errno = 0;
	if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_ADD, connect_fd, &this->_ev) == ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> EPollMultiplexer::clear_fd(int clear_fd) {
	errno = 0;
	if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_DEL, clear_fd, NULL) == ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] epoll_ctl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

namespace {
	const int KEVENT_TIMEOUT = 0;
	const int INIT_KQ = -1;
	const int EVENT_COUNT = 1;
	const int IO_TIMEOUT = -1;

	const int ERROR = -1;

	Result<int, std::string> init_kqueue() {
		int kq;

		errno = 0;
		kq = kqueue();
		if (kq == ERROR) {
			return Result<int, std::string>::err(strerror(errno));
		}
		return Result<int, std::string>::ok(kq);
	}

	Result<int, std::string> kevent_register(int kq, struct kevent *change_event) {
		errno = 0;
		if (kevent(kq, change_event, EVENT_COUNT, NULL, 0, NULL) == ERROR) {
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
		if (events == ERROR) {
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

KqueueMultiplexer::KqueueMultiplexer(int socket_fd) : _socket_fd(socket_fd),
													  _kq(INIT_KQ),
													  _change_event(),
													  _new_event() {
	Result<int, std::string> kq_result, kevent_result;

	DEBUG_SERVER_PRINT("[I/O multiplexer : kqueue]");

	kq_result = init_kqueue();
	if (kq_result.is_err()) {
		std::string err_info = create_error_info(kq_result.get_err_value(), __FILE__, __LINE__);
		throw std::runtime_error("[Server Error] kqueue:" + err_info);
	}
	this->_kq = kq_result.get_ok_value();

	EV_SET(&this->_change_event, this->_socket_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	kevent_result = kevent_register(this->_kq, &this->_change_event);
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

	kevent_result = kevent_wait(this->_kq, &this->_new_event);
	if (kevent_result.is_err()) {
		std::string err_info = create_error_info(kevent_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] kevent:" + err_info);
	}
	new_events = kevent_result.get_ok_value();
	if (new_events == KEVENT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	cast_result = cast_fd_uintptr_to_int(this->_new_event.ident);
	if (cast_result.is_err()) {
		std::string err_info = create_error_info(cast_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error]" + err_info);
	}
	return Result<int, std::string>::ok(cast_result.get_ok_value());
}

Result<int, std::string> KqueueMultiplexer::register_connect_fd(int connect_fd) {
	EV_SET(&this->_change_event, connect_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	return kevent_register(this->_kq, &this->_change_event);
}

Result<int, std::string> KqueueMultiplexer::clear_fd(int clear_fd) {
	Result<int, std::string> kevent_result;
	std::string err_str, err_info;

	EV_SET(&this->_change_event, clear_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	kevent_result = kevent_register(this->_kq, &this->_change_event);
	if (kevent_result.is_err()) {
		err_info = create_error_info(kevent_result.get_err_value(), __FILE__, __LINE__);
		err_str = "kevent:" + err_info;
	}
	errno = 0;
	if (close(clear_fd) == ERROR) {
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
	const int INIT_FD = -1;
	const int MAX_SESSION = 128;
	const int SELECT_TIMEOUT = 0;
	const int IO_TIMEOUT = -1;

	int ERROR = -1;

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
		if (select_ret == ERROR) {
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
		return Result<int, int>::err(ERROR);
	}
}  // namespace

SelectMultiplexer::SelectMultiplexer(int socket_fd) {
	DEBUG_SERVER_PRINT("[I/O multiplexer : select]");

	this->_socket_fd = socket_fd;
	this->_connect_fds = std::vector<int>(MAX_SESSION, INIT_FD);
	this->_fds = init_fds(this->_socket_fd, this->_connect_fds);
}

SelectMultiplexer::~SelectMultiplexer() {
	for (int i = 0; i < MAX_SESSION; ++i) {
		if (this->_connect_fds[i] == INIT_FD) {
			continue;
		}
		errno = 0;
		if (close(this->_connect_fds[i]) == ERROR) {
			std::string err_info = create_error_info(errno, __FILE__, __LINE__);
			std::cerr << "[Error] close:" << err_info << std::endl;
		}
		this->_connect_fds[i] = INIT_FD;
	}
}

Result<int, std::string> SelectMultiplexer::get_io_ready_fd() {
	int max_fd;
	Result<int, std::string> select_result;
	Result<int, int> fd_result;

	this->_fds = init_fds(this->_socket_fd, this->_connect_fds);
	max_fd = get_max_fd(this->_connect_fds, this->_socket_fd);
	select_result = select_fds(max_fd, &this->_fds);
	if (select_result.is_err()) {
		std::string err_info = create_error_info(select_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] select:" + err_info);
	}
	if (select_result.get_ok_value() == SELECT_TIMEOUT) {
		return Result<int, std::string>::ok(IO_TIMEOUT);
	}

	fd_result = get_ready_fd(this->_connect_fds, &this->_fds, this->_socket_fd);
	if (fd_result.is_err()) {
		std::string err_info = create_error_info("ready fd not found", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] " + err_info);
	}
	return Result<int, std::string>::ok(fd_result.get_ok_value());
}

Result<int, std::string> SelectMultiplexer::clear_fd(int clear_fd) {
	std::vector<int>::iterator fd = std::find(this->_connect_fds.begin(),
											  this->_connect_fds.end(),
											  clear_fd);
	if (fd == this->_connect_fds.end()) {
		std::string err_info = create_error_info("clear fd not found", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] " + err_info);
	}

	FD_CLR(*fd, &this->_fds);
	errno = 0;
	if (close(*fd) == ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("close:" + err_info);
	}
	*fd = INIT_FD;
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> SelectMultiplexer::register_connect_fd(int connect_fd) {
	std::vector<int>::iterator fd = std::find(this->_connect_fds.begin(),
											  this->_connect_fds.end(),
											  INIT_FD);
	if (fd == this->_connect_fds.end()) {
		std::string err_info = create_error_info("over max connection", __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Info] " + err_info);
	}
	*fd = connect_fd;
	return Result<int, std::string>::ok(OK);
}

#endif
