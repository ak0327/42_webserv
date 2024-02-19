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
#include "Constant.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"

extern char **environ;


Result<int, std::string> HttpResponse::create_socketpair(int socket_fds[2]) {
    std::string err_info;

    errno = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, FLAG_NONE, socket_fds) == SOCKETPAIR_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        return Result<int, std::string>::err(err_info);
    }
    return Result<int, std::string>::ok(OK);
}


std::vector<char *> HttpResponse::get_argv_for_execve(const std::vector<std::string> &interpreter,
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


int HttpResponse::execute_cgi_script_in_child(int socket_fds[2],
                                const std::string &file_path,
                                const std::string &query) {
    Result<std::vector<std::string>, int> interpreter_result;
    std::vector<std::string> interpreter;
    std::vector<char *> argv;
    std::string err_info;
    (void)query;

    interpreter_result = HttpResponse::get_interpreter(file_path);
    if (interpreter_result.is_err()) {
        return EXIT_FAILURE;
    }
    interpreter = interpreter_result.get_ok_value();

    argv = get_argv_for_execve(interpreter, file_path);

    errno = 0;
    if (close(socket_fds[READ]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }

    errno = 0;
    if (dup2(socket_fds[WRITE], STDOUT_FILENO) == DUP_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }

    errno = 0;
    if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }

    execve(argv[0], argv.data(), environ);

    const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
    std::cerr << error_msg << std::endl;  // todo: tmp -> log?
    return EXIT_FAILURE;
}


bool HttpResponse::is_exec_timeout(time_t start_time, int timeout_sec) {
    time_t current_time = time(NULL);
    double elapsed_time = difftime(current_time, start_time);

    return (timeout_sec <= elapsed_time);
}


Result<std::vector<std::string>, int> HttpResponse::get_interpreter(const std::string &file_path) {
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


void skip_field_lines(std::istringstream *iss) {
    std::string line;

    while (getline(*iss, line) && !line.empty()) {}
}


// todo: tmp
// 一旦、ヘッダーを全て削除し、bodyのみとする
// field-lineはparseしたり、上流のfield-lineとの結合が必要...
Result<std::string, int> translate_to_http_protocol(const std::string &cgi_result) {
    std::string	cgi_body, line;
    std::istringstream iss(cgi_result);

    skip_field_lines(&iss);

    while (getline(iss, line)) {
        line.append(std::string(LF, 1));
        cgi_body.append(line);
    }
    // std::cout << YELLOW << "cgi_body[" << cgi_body << "]" << RESET << std::endl;
    return Result<std::string, int>::ok(cgi_body);
}


Result<Fd, int> HttpResponse::exec_cgi(const std::string &file_path,
                                       int *cgi_read_fd,
                                       pid_t *cgi_pid,
                                       int *status_code) {
    Result<std::string, int> execute_cgi_result, translate_result;
    Result<int, std::string> socketpair_result;
    std::string err_info;
    int			socket_fds[2];
    pid_t		pid;

    if (!cgi_read_fd || !cgi_pid || !status_code) {
        return Result<Fd, int>::err(ERR);  // todo: tmp
    }

    socketpair_result = create_socketpair(socket_fds);
    if (socketpair_result.is_err()) {
        err_info = socketpair_result.get_err_value();
        std::cerr << "[Error] socketpair: " << err_info << std::endl;  // todo: tmp
        *status_code = STATUS_SERVER_ERROR;
        return Result<Fd, int>::err(ERR);  // todo: tmp
    }

    errno = 0;
    pid = fork();
    if (pid == FORK_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        *status_code = STATUS_SERVER_ERROR;
        return Result<Fd, int>::err(ERR);  // todo: tmp
    }

    if (pid == CHILD_PROC) {
        std::string query;  // todo: get query
        std::exit(execute_cgi_script_in_child(socket_fds, file_path, query));
    }

    errno = 0;
    if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
        close(socket_fds[READ]);
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        *status_code = STATUS_SERVER_ERROR;
        return Result<Fd, int>::err(ERR);
    }
    *cgi_read_fd = socket_fds[READ];
    *cgi_pid = pid;
    return Result<Fd, int>::ok(socket_fds[READ]);
}
