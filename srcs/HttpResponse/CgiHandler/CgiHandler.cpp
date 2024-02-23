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
#include "CgiHandler.hpp"
#include "Color.hpp"
#include "ConfigStruct.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpMessageParser.hpp"
#include "HttpRequest.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"

extern char **environ;

CgiHandler::CgiHandler()
    : cgi_read_fd_(INIT_FD),
      cgi_pid_(INIT_PID),
      timeout_duration_sec_(ConfigInitValue::kDefaultCgiTimeoutSec),
      media_type_(),
      cgi_status_(StatusOk),
      recv_buf_() {}


CgiHandler::~CgiHandler() {
    clear_cgi_process();
}


void CgiHandler::clear_cgi_process() {
    kill_cgi_process();
    close_cgi_fd();
}


void CgiHandler::kill_cgi_process() {
    if (pid() == INIT_PID) {
        DEBUG_PRINT(RED, "kill pid is init at %zu -> return", std::time(NULL));
        return;
    }

    // int process_status;
    // if (!is_processing(&process_status)) {
    //     return;
    // }
    errno = 0;
    DEBUG_PRINT(RED, "kill pid: %d at %zu", pid(), std::time(NULL));

    if (kill(pid(), SIGKILL) == KILL_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    // set_cgi_pid(INIT_PID);
}


void CgiHandler::close_cgi_fd() {
    DEBUG_PRINT(YELLOW, "cgi: close fd: %d", fd());
    if (fd() == INIT_FD) {
        return;
    }

    errno = 0;
    if (close(fd()) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    set_cgi_read_fd(INIT_FD);  // todo: success only?
}


Result<int, std::string> CgiHandler::create_socketpair(int socket_fds[2]) {
    errno = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, FLAG_NONE, socket_fds) == SOCKETPAIR_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}


std::vector<char *> CgiHandler::get_argv_for_execve(const std::vector<std::string> &interpreter,
                                                      const std::string &file_path) {
    std::vector<char *> argv;

    std::vector<std::string>::const_iterator itr;
    for (itr = interpreter.begin(); itr != interpreter.end(); ++itr) {
        argv.push_back(const_cast<char *>((*itr).c_str()));
    }
    argv.push_back(const_cast<char *>(file_path.c_str()));
    argv.push_back(NULL);
    return argv;
}


Result<std::vector<std::string>, ProcResult> CgiHandler::get_interpreter(const std::string &file_path) {
    std::ifstream file(file_path.c_str());

    if (file.fail()) {
        return Result<std::vector<std::string>, ProcResult>::err(Failure);
    }
    std::string shebang_line;
    std::getline(file, shebang_line);

    std::istringstream iss(shebang_line);
    std::vector<std::string> interpreter;
    std::string	word;
    while (getline(iss, word, ' ')) {
        interpreter.push_back(word);
    }
    file.close();

    if (interpreter.empty()) {
        return Result<std::vector<std::string>, ProcResult>::err(Failure);
    }

    std::vector<std::string>::iterator itr = interpreter.begin();
    const std::size_t kSHEBANG_LEN = 2;
    if (kSHEBANG_LEN <= (*itr).length() && (*itr)[0] == '#' && (*itr)[1] == '!') {
        *itr = (*itr).substr(kSHEBANG_LEN);
        return Result<std::vector<std::string>, ProcResult>::ok(interpreter);
    }
    return Result<std::vector<std::string>, ProcResult>::err(Failure);
}


void skip_field_lines(std::istringstream *iss) {
    std::string line;

    while (getline(*iss, line) && !line.empty()) {}
}


// Result<ProcResult, StatusCode> CgiHandler::recv_cgi_output() {
//     ssize_t recv_size = recv_to_buf(this->fd());
//     // if (recv_size == RECV_CLOSED) {
//     //     return Result<ProcResult, StatusCode>::ok(ConnectionClosed);
//     // }
//     DEBUG_PRINT(YELLOW, "      recv_size: %zd", recv_size);
//     // if (recv_size == RECV_CLOSED) {
//     //     DEBUG_PRINT(YELLOW, "     recv_size: %zd", recv_size);
//     //     if (this->is_executing_cgi()) {
//     //         DEBUG_PRINT(YELLOW, "      kill cgi proc");
//     //         this->cgi_handler_.kill_cgi_process();
//     //     }
//     //     return Result<ProcResult, StatusCode>::ok(ConnectionClosed);
//
//     int process_exit_status;
//     if (is_processing(&process_exit_status)) {
//         return Result<ProcResult, StatusCode>::ok(Continue);
//     }
//     DEBUG_PRINT(YELLOW, "     process_exit_status: %d", process_exit_status);
//     if (process_exit_status != EXIT_SUCCESS) {
//         return Result<ProcResult, StatusCode>::err(InternalServerError);
//     }
//     close_cgi_fd();
//     return Result<ProcResult, StatusCode>::ok(Success);
// }


StatusCode CgiHandler::parse_document_response() {
    StatusCode cgi_status = StatusOk;
    int status_count = 0;
    while (true) {
        Result<std::string, ProcResult> line_result = pop_line_from_buf();
        if (line_result.is_err()) {
            return InternalServerError;  // no line in buf
        }
        std::string field_line = line_result.get_ok_value();
        if (field_line.empty()) {
            break;
        }
        std::string	field_name, field_value;
        Result<ProcResult, StatusCode> split = HttpRequest::split_field_line(field_line,
                                                                             &field_name,
                                                                             &field_value);
        if (split.is_err()) {
            return InternalServerError;
        }
        field_name = StringHandler::to_lower(field_name);
        if (field_name == std::string(CONTENT_TYPE)) {
            if (this->media_type_.is_ok()) {
                return InternalServerError;
            }
            this->media_type_ = MediaType(field_value);
            if (this->media_type_.is_err()) {
                return InternalServerError;
            }
        } else if (field_name == "status") {
            ++status_count;
            if (1 < status_count) {
                return InternalServerError;
            }
            bool succeed;
            int code = HttpMessageParser::to_integer_num(field_value, &succeed);
            if (!succeed) {
                return InternalServerError;
            }
            Result<StatusCode, ProcResult> convert_result = HttpMessageParser::convert_to_enum(code);
            if (convert_result.is_err()) {
                return InternalServerError;
            }
            cgi_status = convert_result.get_ok_value();
        }
    }
    if (this->media_type_.is_err()) {
        return InternalServerError;
    }
    return cgi_status;
}


ssize_t CgiHandler::recv_to_buf(int fd) {
    return HttpRequest::recv_to_buf(fd, &this->recv_buf_);
}


// string NL
//        ^return
void CgiHandler::find_nl(const std::vector<unsigned char> &data,
                           std::vector<unsigned char>::const_iterator start,
                           std::vector<unsigned char>::const_iterator *nl) {
    if (!nl) {
        return;
    }
    std::vector<unsigned char>::const_iterator itr = start;
    while (itr != data.end() && itr + 1 != data.end()) {
        if (*itr == NL) {
            *nl = itr;
            return;
        }
        ++itr;
    }
    *nl = data.end();
}


// line NL next_line
// ^^^^    ^ret
Result<std::string, ProcResult> CgiHandler::get_line(const std::vector<unsigned char> &data,
                                                       std::vector<unsigned char>::const_iterator start,
                                                       std::vector<unsigned char>::const_iterator *ret) {
    if (!ret) {
        return Result<std::string, ProcResult>::err(FatalError);
    }

    std::vector<unsigned char>::const_iterator nl;
    CgiHandler::find_nl(data, start, &nl);
    if (nl == data.end()) {
        *ret = data.end();
        return Result<std::string, ProcResult>::err(Failure);
    }

    std::string line(start, nl);
    *ret = nl + 1;
    return Result<std::string, ProcResult>::ok(line);
}


Result<std::string, ProcResult> CgiHandler::pop_line_from_buf() {
    std::vector<unsigned char>::const_iterator next_line;

    Result<std::string, ProcResult> result = get_line(this->recv_buf_,
                                                      this->recv_buf_.begin(),
                                                      &next_line);
    if (result.is_err()) {
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string line = result.get_ok_value();
    HttpRequest::trim(&this->recv_buf_, next_line);

    std::string debug_buf(this->recv_buf_.begin(), this->recv_buf_.end());
    DEBUG_SERVER_PRINT("buf[%s]", debug_buf.c_str());
    return Result<std::string, ProcResult>::ok(line);
}


int CgiHandler::exec_script_in_child(int socket_fds[2],
                                     const std::string &file_path,
                                     const std::string &query) {
    Result<std::vector<std::string>, ProcResult> interpreter_result;
    std::vector<std::string> interpreter;
    std::vector<char *> argv;  // todo: char *const argv[]
    (void)query;  // todo

    DEBUG_PRINT(CYAN, "    cgi(child) 1");

    interpreter_result = CgiHandler::get_interpreter(file_path);
    if (interpreter_result.is_err()) {
        return EXIT_FAILURE;
    }
    interpreter = interpreter_result.get_ok_value();

    argv = get_argv_for_execve(interpreter, file_path);

    DEBUG_PRINT(CYAN, "    cgi(child) 2");
    errno = 0;
    if (close(socket_fds[READ]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }

    DEBUG_PRINT(CYAN, "    cgi(child) 3");
    errno = 0;
    if (dup2(socket_fds[WRITE], STDOUT_FILENO) == DUP_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }
    DEBUG_PRINT(CYAN, "    cgi(child) 4");

    errno = 0;
    if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }
    DEBUG_PRINT(CYAN, "    cgi(child) 5");

    errno = 0;
    if (execve(argv[0], argv.data(), environ) == EXECVE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return EXIT_FAILURE;
    }
    DEBUG_PRINT(CYAN, "    cgi(child) 6");
    return EXIT_FAILURE;
}


StatusCode CgiHandler::exec_script(const std::string &file_path) {
    Result<int, std::string> socketpair_result;
    int socket_fds[2];

    DEBUG_PRINT(CYAN, "   cgi 1");
    socketpair_result = create_socketpair(socket_fds);
    if (socketpair_result.is_err()) {
        const std::string error_msg = socketpair_result.get_err_value();
        std::cerr << "[Error] socketpair: " << error_msg << std::endl;  // todo: tmp
        return InternalServerError;  // todo: tmp
    }
    DEBUG_PRINT(CYAN, "   cgi 2");

    errno = 0;
    pid_t pid = fork();
    if (pid == FORK_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        return InternalServerError;  // todo: tmp
    }

    DEBUG_PRINT(CYAN, "   cgi 3");
    if (pid == CHILD_PROC) {
        DEBUG_PRINT(CYAN, "   cgi 4 child(pid: %d)", pid);
        std::string query;  // todo: get query
        std::exit(exec_script_in_child(socket_fds, file_path, query));
    } else {
        DEBUG_PRINT(CYAN, "   cgi 4 parent(pid: %d)", pid);
        errno = 0;
        if (close(socket_fds[WRITE]) == CLOSE_ERROR) {
            close(socket_fds[READ]);
            const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
            std::cerr << error_msg << std::endl;  // todo: tmp
            return InternalServerError;
        }

        Result<int, std::string> result = Socket::set_fd_to_nonblock(socket_fds[READ]);
        if (result.is_err()) {
            std::cerr << result.get_err_value() << std::endl;
            return InternalServerError;
        }
        set_cgi_read_fd(socket_fds[READ]);
        set_cgi_pid(pid);
        set_timeout_limit();

        DEBUG_PRINT(CYAN, "   cgi 5(fd: %d, pid: %d) start_time: %zu, limit: %zu", this->fd(), this->pid(), std::time(NULL), this->timeout_limit());
        return StatusOk;
    }
}



bool CgiHandler::is_processing(int *status) {
    DEBUG_PRINT(YELLOW, "    is_cgi_processing 1 pid: %d at %zu", pid(), std::time(NULL));
    // if (pid() == INIT_PID) {
    //     DEBUG_PRINT(YELLOW, "    is_cgi_processing 2 pid == init -> killed");
    //     // killed
    //     *status = EXIT_FAILURE;
    //     return false;
    // }

    int child_status;
    errno = 0;
    pid_t wait_result = waitpid(pid(), &child_status, WNOHANG);
    int tmp_err = errno;
    DEBUG_PRINT(YELLOW, "    is_cgi_processing 3");
    DEBUG_PRINT(YELLOW, "     wait_result: %d, errno: %d(ECHILD: %d)", wait_result, tmp_err, ECHILD);
    if (tmp_err != 0) {
        DEBUG_PRINT(YELLOW, "    is_cgi_processing 4");
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(tmp_err);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    if (wait_result == PROCESSING || (wait_result == WAIT_ERROR && tmp_err != ECHILD)) {
        DEBUG_PRINT(YELLOW, "    is_cgi_processing 5 -> continue");
        return true;
    }

    DEBUG_PRINT(YELLOW, "    is_cgi_processing 6");
    if (0 < wait_result && status) {
        if (WIFSIGNALED(child_status)) {
            int term_sig = WTERMSIG(child_status);
            *status = EXIT_FAILURE;
            DEBUG_PRINT(YELLOW, "    Child terminated by signal: %d", term_sig);
        }
        *status = WEXITSTATUS(child_status);
        DEBUG_PRINT(YELLOW, "    is_cgi_processing 7 status: %d", *status);
    } else if (tmp_err == ECHILD && status) {
        // term by sig?
        *status = EXIT_FAILURE;
        int term_sig = WTERMSIG(child_status);
        DEBUG_PRINT(YELLOW, "    Child terminated by signal: %d", term_sig);
    }
    DEBUG_PRINT(YELLOW, "    is_cgi_processing 8 pid set to init -> next");
    set_cgi_pid(INIT_PID);
    return false;
}


void CgiHandler::set_cgi_read_fd(int read_fd) { this->cgi_read_fd_ = read_fd; }

void CgiHandler::set_cgi_pid(pid_t pid) {
    DEBUG_PRINT(RED, "set_pid  %d -> %d", this->pid(), pid);
    this->cgi_pid_ = pid;
}

void CgiHandler::set_timeout_limit() {
    this->timeout_limit_ = std::time(NULL) + this->timeout_duration_sec();
    DEBUG_PRINT(YELLOW, "set_timeout_limit: %zu", this->timeout_limit());
}


void CgiHandler::clear_buf() {
    this->recv_buf_.clear();
}

int CgiHandler::fd() const { return this->cgi_read_fd_; }
pid_t CgiHandler::pid() const { return this->cgi_pid_; }
StatusCode CgiHandler::status_code() const { return this->cgi_status_; }
time_t CgiHandler::timeout_limit() const { return this->timeout_limit_; }
time_t CgiHandler::timeout_duration_sec() const { return this->timeout_duration_sec_; }
const std::vector<unsigned char> &CgiHandler::cgi_body() const { return this->recv_buf_; }

bool CgiHandler::is_process_timeout() const {
    time_t current_time = std::time(NULL);
    return (this->timeout_limit() < current_time);
}
