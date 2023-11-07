#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include "Color.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"

extern char **environ;

// todo: mv Const.h
namespace {

const int OK = 0;
const int ERR = -1;
const int IO_TIMEOUT = -1;

const int CLOSE_ERROR = -1;
const int DUP_ERROR = -1;
const int FORK_ERROR = -1;
const int KILL_ERROR = -1;
const int SOCKETPAIR_ERROR = -1;

const pid_t WAIT_ERROR = -1;
const ssize_t RECV_ERROR = -1;

const int FLAG_NONE = 0;
const int CHILD_PROC = 0;

const std::size_t READ = 0;
const std::size_t WRITE = 1;

Result<int, std::string> create_socketpair(int socket_fds[2]) {
	std::string err_info;

	errno = 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, FLAG_NONE, socket_fds) == SOCKETPAIR_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp
		return Result<int, std::string>::err(err_info);
	}
	return Result<int, std::string>::ok(OK);
}

std::vector<char *> get_argv_for_execve(const std::vector<std::string> &interpreter,
										const std::string &file_path) {
	Result<std::vector<std::string>, int> result;
	std::vector<std::string>::const_iterator itr;
	std::vector<char *> argv;

	for (itr = interpreter.begin(); itr != interpreter.end(); ++itr) {
		argv.push_back(const_cast<char *>((*itr).c_str()));
	}
	argv.push_back(const_cast<char *>(file_path.c_str()));
	argv.push_back(NULL);
	return argv;
}

int execute_cgi_script_in_child(int socket_fds[2],
							 const std::string &file_path,
							 const std::string &query) {
	Result<std::vector<std::string>, int> interpreter_result;
	std::vector<std::string> interpreter;
	std::vector<char *> argv;
	std::string err_info;
	(void)query;

	interpreter_result = get_interpreter(file_path);
	if (interpreter_result.is_err()) {
		return EXIT_FAILURE;
	}
	interpreter = interpreter_result.get_ok_value();

	argv = get_argv_for_execve(interpreter, file_path);

	errno = 0;
	if (close(socket_fds[READ]) == CLOSE_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp -> log?
		return EXIT_FAILURE;
	}

	errno = 0;
	if (dup2(socket_fds[WRITE], STDOUT_FILENO) == DUP_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp -> log?
		return EXIT_FAILURE;
	}

	errno = 0;
	if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp -> log?
		return EXIT_FAILURE;
	}

	execve(argv[0], argv.data(), environ);

	err_info = create_error_info(errno, __FILE__, __LINE__);
	std::cerr << err_info << std::endl;  // todo: tmp -> log?
	return EXIT_FAILURE;
}

bool is_exec_timeout(time_t start_time, int timeout_sec) {
	time_t current_time = time(NULL);
	double elapsed_time = difftime(current_time, start_time);

	return (timeout_sec <= elapsed_time);
}

}  // namespace


Result<std::vector<std::string>, int> get_interpreter(const std::string &file_path) {
	std::vector<std::string> interpreter;
	std::ifstream		file;
	std::string			shebang_line;
	std::string			word;
	const std::size_t	kSHEBANG_LEN = 2;

	file.open(file_path.c_str());
	if (file.fail()) {
		return Result<std::vector<std::string>, int>::err(ERR);
	}

	std::getline(file, shebang_line);

	std::istringstream	iss(shebang_line);

	while (getline(iss, word, ' ')) {
		interpreter.push_back(word);
	}
	file.close();

	std::vector<std::string>::iterator itr;
	itr = interpreter.begin();
	if (itr == interpreter.end()) {
		return Result<std::vector<std::string>, int>::err(ERR);
	}

	if (kSHEBANG_LEN <= (*itr).length() && (*itr)[0] == '#' && (*itr)[1] == '!') {
		*itr = (*itr).substr(kSHEBANG_LEN);
		return Result<std::vector<std::string>, int>::ok(interpreter);
	}
	return Result<std::vector<std::string>, int>::err(ERR);
}

Result<int, int> wait_for_io_ready(int fd) {
	Result<int, std::string> fd_ready_result;
	IOMultiplexer	*fds = NULL;
	std::string		err_info;
	int				ready_fd;
	bool			is_error = false;
	bool 			is_timeout = false;

	try {
#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)
		fds = new EPollMultiplexer(fd);
#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)
		fds = new KqueueMultiplexer(fd);
#else
		fds = new SelectMultiplexer(fd);
#endif

		while (true) {
			fd_ready_result = fds->get_io_ready_fd();
			if (fd_ready_result.is_err()) {
				err_info = fd_ready_result.get_err_value();
				is_error |= true;
				break;
			}
			if (fd_ready_result.get_ok_value() == IO_TIMEOUT) {
				is_timeout |= true;
				break;
			}
			ready_fd = fd_ready_result.get_ok_value();
			break;
		}

		delete fds;
		if (is_error) {
			std::cerr << err_info << std::endl;  // todo: tmp
			return Result<int, int>::err(ERR);
		}
		if (is_timeout) {
			std::cerr << "[CGI Error] timeout" << std::endl;  // todo: tmp
			return Result<int, int>::ok(IO_TIMEOUT);
		}
		return Result<int, int>::ok(ready_fd);
	} catch (std::bad_alloc const &e) {
		err_info = create_error_info("Failed to allocate memory", __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp
		return Result<int, int>::err(ERR);
	}
}

Result<int, int> wait_child_process(pid_t child_pid) {
	int			child_status;
	pid_t		wait_result;
	std::string err_info;

	errno = 0;
	child_status = EXIT_SUCCESS;
	wait_result = waitpid(child_pid, &child_status, WNOHANG);
	child_status = WEXITSTATUS(child_status);

	if (wait_result == child_pid) {
		return Result<int, int>::ok(child_status);
	}

	if (wait_result == WAIT_ERROR) {
		if (errno == ECHILD) {
			return Result<int, int>::ok(child_status);
		}
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;
		return Result<int, int>::err(ERR);
	}

	if (kill(child_pid, SIGKILL) == KILL_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;
		return Result<int, int>::err(ERR);
	}

	if (waitpid(child_pid, &child_status, FLAG_NONE) == WAIT_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(child_status);
}

Result<std::string, int> recv_cgi_result(int read_fd, bool *is_error, bool *is_timeout) {
	time_t		start_time;
	std::string	cgi_result;
	int			kTIMEOUT_SEC = 2;
	ssize_t 	read_bytes;
	std::string err_info;
	char		buf[BUFSIZ];

	start_time = time(NULL);
	cgi_result = "";
	while (true) {
		if (*is_error || *is_timeout) {
			break;
		}

		if (is_exec_timeout(start_time, kTIMEOUT_SEC)) {
			*is_timeout |= true;
			break;
		}

		errno = 0;
		read_bytes = recv(read_fd, buf, BUFSIZ - 1, FLAG_NONE);
		if (read_bytes == RECV_ERROR) {
			err_info = create_error_info(errno, __FILE__, __LINE__);
			std::cerr << err_info << std::endl;  // todo: tmp
			*is_error |= true;
			break;
		}
		if (read_bytes == 0) {
			break;
		}
		buf[read_bytes] = '\0';
		cgi_result.append(buf);
	}

	if (*is_timeout) {
		return Result<std::string, int>::err(ERR);
	}
	if (*is_error) {
		return Result<std::string, int>::err(ERR);
	}
	return Result<std::string, int>::ok(cgi_result);
}

Result<std::string, int> get_cgi_result_via_socket(int socket_fds[2], int pid) {
	Result<int, int> io_result, wait_result;
	Result<std::string, int> recv_result;
	std::string	cgi_result;
	std::string err_info;
	bool		is_error = false;
	bool		is_timeout = false;
	int			child_status;

	errno = 0;
	if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp
		return Result<std::string, int>::err(STATUS_SERVER_ERROR);
	}

	io_result = wait_for_io_ready(socket_fds[READ]);
	if (io_result.is_err()) {
		is_error |= true;
	} else if (io_result.get_ok_value() == IO_TIMEOUT) {
		is_timeout |= true;
	}

	recv_result = recv_cgi_result(socket_fds[READ], &is_error, &is_timeout);
	if (recv_result.is_ok()) {
		cgi_result = recv_result.get_ok_value();
	}

	errno = 0;
	if (close(socket_fds[READ]) == CLOSE_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp
		is_error |= true;
	}

	wait_result = wait_child_process(pid);
	if (wait_result.is_err()) {
		is_error |= true;
	}
	child_status = wait_result.get_ok_value();
	if (child_status != EXIT_SUCCESS) {
		is_error |= true;
	}

	if (is_timeout) {
		std::cerr << "[Error] CGI Script Execution Timeout" << std::endl;  // todo: tmp
		return Result<std::string, int>::err(STATUS_BAD_REQUEST);  // todo: tmp
	}
	if (is_error) {
		return Result<std::string, int>::err(STATUS_SERVER_ERROR);  // todo: tmp
	}
	return Result<std::string, int>::ok(cgi_result);
}

void skip_field_lines(std::istringstream *iss) {
	std::string line;

	while (getline(*iss, line) && !line.empty()) {}
}

// todo: tmp
// 一旦、ヘッダーを全て削除し、bodyのみとする
// field-lineはparseしたり、上流のfield-lineとの結合が必要...
Result<std::string, int> translate_to_http_protocol(const std::string &cgi_result) {
	std::string			cgi_body, line;
	std::istringstream	iss(cgi_result);

	skip_field_lines(&iss);

	while (getline(iss, line)) {
		line.append(LF);
		cgi_body.append(line);
	}
	// std::cout << YELLOW << "cgi_body[" << cgi_body << "]" << RESET << std::endl;
	return Result<std::string, int>::ok(cgi_body);
}

Result<std::string, int> HttpResponse::get_cgi_result(const std::string &file_path,
													  const std::string &query) const {
	Result<std::string, int> execute_cgi_result, translate_result;
	Result<int, std::string> socketpair_result;
	std::string err_info;
	int			socket_fds[2];
	pid_t		pid;

	socketpair_result = create_socketpair(socket_fds);
	if (socketpair_result.is_err()) {
		err_info = socketpair_result.get_err_value();
		std::cerr << "[Error] socketpair: " << err_info << std::endl;  // todo: tmp
		return Result<std::string, int>::err(STATUS_SERVER_ERROR);  // todo: tmp
	}

	errno = 0;
	pid = fork();
	if (pid == FORK_ERROR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		std::cerr << err_info << std::endl;  // todo: tmp
		return Result<std::string, int>::err(STATUS_SERVER_ERROR);  // todo: tmp
	}

	if (pid == CHILD_PROC) {
		std::exit(execute_cgi_script_in_child(socket_fds, file_path, query));
	}

	execute_cgi_result = get_cgi_result_via_socket(socket_fds, pid);
	if (execute_cgi_result.is_err()) {
		return Result<std::string, int>::err(execute_cgi_result.get_err_value());
	}
	return translate_to_http_protocol(execute_cgi_result.get_ok_value());
}
