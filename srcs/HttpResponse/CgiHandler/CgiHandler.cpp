#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <limits>
#include <iostream>
#include <sstream>
#include <vector>
#include "CgiHandler.hpp"
#include "Color.hpp"
#include "ConfigParser.hpp"
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


CgiHandler::CgiHandler()
    : cgi_read_fd_(INIT_FD),
      cgi_write_fd_(INIT_FD),
      cgi_pid_(INIT_PID),
      timeout_duration_sec_(ConfigInitValue::kDefaultCgiTimeoutSec),
      params_(),
      media_type_(),
      cgi_status_(StatusOk),
      send_size_(0),
      recv_buf_() {
}


CgiHandler::~CgiHandler() {
    clear_cgi_process();
}


void CgiHandler::clear_cgi_process() {
    kill_cgi_process();
    close_read_fd();
    close_write_fd();
}


void CgiHandler::kill_cgi_process() {
    if (pid() == INIT_PID) {
        DEBUG_PRINT(GRAY, "[kill_cgi_process] kill pid nothing at %zu -> return", std::time(NULL));
        return;
    }

    DEBUG_PRINT(WHITE, "[kill_cgi_process] kill pid: %d at %zu", pid(), std::time(NULL));
    int status = -1;
    if (!is_processing(&status)) {
        DEBUG_PRINT(WHITE, "[kill_cgi_process] child status: %d", status);
        return;
    }
    if (this->pid() == INIT_PID) { return; }
    errno = 0;
    if (kill(this->pid(), SIGKILL) == KILL_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        DEBUG_PRINT(WHITE, "[kill_cgi_process] kill: %s", error_msg.c_str());
    }
    if (is_processing(&status, FLAG_NONE)) {
        // for debug
        DEBUG_PRINT(WHITE, "[kill_cgi_process] kill failure ??");
    } else {
        // for debug
        DEBUG_PRINT(WHITE, "[kill_cgi_process] kill success");
    }
}


void CgiHandler::close_read_fd() {
    DEBUG_PRINT(WHITE, "cgi: close read_fd: %d", this->read_fd());
    if (this->read_fd() == INIT_FD) {
        return;
    }

    errno = 0;
    if (close(this->read_fd()) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    set_cgi_read_fd(INIT_FD);  // todo: success only?
}


void CgiHandler::close_write_fd() {
    DEBUG_PRINT(WHITE, "cgi: close write_fd: %d", write_fd());
    if (write_fd() == INIT_FD) {
        return;
    }

    errno = 0;
    if (close(write_fd()) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: log
    }
    set_cgi_write_fd(INIT_FD);  // todo: success only?
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


void CgiHandler::strcpy(char *dst, const char *src) {
    std::size_t i = 0;
    while (src[i]) {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}


char **CgiHandler::create_argv(const std::string &file_path) {
    Result<std::vector<std::string>, ProcResult> interpreter_result;
    interpreter_result = CgiHandler::get_interpreter(file_path);
    if (interpreter_result.is_err()) {
        return NULL;
    }
    std::vector<std::string> interpreter = interpreter_result.ok_value();

    std::vector<std::string> argv_strings = interpreter;
    argv_strings.push_back(file_path);

    char **argv = NULL;
    try {
        argv = new char*[argv_strings.size() + 1];
        for (size_t i = 0; i < argv_strings.size(); ++i) {
            argv[i] = new char[argv_strings[i].size() + 1];
            CgiHandler::strcpy(argv[i], argv_strings[i].c_str());
        }
        argv[argv_strings.size()] = NULL;
    }
    catch (const std::bad_alloc &e) {
        delete_char_double_ptr(argv);
        argv = NULL;
    }
    return argv;
}


std::string CgiHandler::make_env_elem(const std::string &key,
                                      const std::string &value) {
    return key + "=" + value;
}


char **CgiHandler::create_envp(const CgiParams &params) {
    std::ostringstream content_length;
    content_length << params.content_length;

    std::vector<std::string> env_strings;
    env_strings.push_back(make_env_elem("CONTENT_LENGTH", content_length.str()));
    if (!params.content_type.empty()) {
        env_strings.push_back(make_env_elem("CONTENT_TYPE", params.content_type));
    }
    env_strings.push_back(make_env_elem("QUERY_STRING", params.query_string));
    env_strings.push_back(make_env_elem("PATH_INFO", params.path_info));
    env_strings.push_back(make_env_elem("SCRIPT_NAME", params.script_path));

    char *path_env = std::getenv("PATH");
    if (path_env != NULL) {
        env_strings.push_back((make_env_elem("PATH", path_env)));
    }

    char **envp = NULL;
    try {
        envp = new char*[env_strings.size() + 1];
        for (size_t i = 0; i < env_strings.size(); ++i) {
            envp[i] = new char[env_strings[i].size() + 1];
            CgiHandler::strcpy(envp[i], env_strings[i].c_str());
        }
        envp[env_strings.size()] = NULL;
    }
    catch (const std::bad_alloc &e) {
        delete_char_double_ptr(envp);
        envp = NULL;
    }
    return envp;
}


void CgiHandler::delete_char_double_ptr(char **ptr) {
    if (!ptr) { return; }

    for (std::size_t i = 0; ptr[i] != NULL; ++i) {
        delete[] ptr[i];
    }
    delete[] ptr;
}


Result<std::vector<std::string>, ProcResult> CgiHandler::get_interpreter(const std::string &file_path) {
    std::ifstream file(file_path.c_str());
    // DEBUG_PRINT(CYAN, "     get_interpreter 1 path: %s", file_path.c_str());

    if (file.fail()) {
        // DEBUG_PRINT(CYAN, "     get_interpreter 2 err");
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
        // DEBUG_PRINT(CYAN, "     get_interpreter 3 err");
        return Result<std::vector<std::string>, ProcResult>::err(Failure);
    }

    // DEBUG_PRINT(CYAN, "     get_interpreter 4");

    const std::size_t kSHEBANG_LEN = 2;
    std::string shebang = interpreter[0];
    if (shebang.length() <= kSHEBANG_LEN || shebang[0] != '#' || shebang[1] != '!') {
        // DEBUG_PRINT(CYAN, "     get_interpreter 5 err");
        return Result<std::vector<std::string>, ProcResult>::err(Failure);
    }

    interpreter[0] = shebang.substr(kSHEBANG_LEN);
    // DEBUG_PRINT(CYAN, "     get_interpreter 6 shebang[%s]", interpreter[0].c_str());
    return Result<std::vector<std::string>, ProcResult>::ok(interpreter);
}


Result<ProcResult, std::string> CgiHandler::send_request_body_to_cgi() {
    return Socket::send_buf(this->write_fd(), &this->params_.content);
}


ProcResult CgiHandler::recv_cgi_output() {
    DEBUG_PRINT(YELLOW, "[recv_cgi_output] recv_to_cgi_buf at %zu", std::time(NULL));
    Result<ProcResult, ErrMsg> result = Socket::recv_to_buf(this->read_fd(), &this->recv_buf_);
    if (result.is_err()) {
        DEBUG_PRINT(BG_YELLOW, "[Error] recv CGI: %s", result.err_value().c_str());
        this->kill_cgi_process();
        return Failure;
    }

    DEBUG_PRINT(YELLOW, "[recv_cgi_output] recv_size: %zd, buf_size: %zu", result.ok_value(), this->recv_buf_.size());
    int process_exit_status;
    if (is_processing(&process_exit_status)) {
        DEBUG_PRINT(YELLOW, " -> recv continue");
        return Continue;
    }
    DEBUG_PRINT(YELLOW, "[recv_cgi_output] process_exit_status: %d", process_exit_status);
    if (process_exit_status == EXIT_SUCCESS) {
        DEBUG_PRINT(YELLOW, " -> recv success");
        return Success;
    }

    clear_recv_buf();
    DEBUG_PRINT(YELLOW, " -> recv failure or timeout, clear buf");
    return process_exit_status == PROCESS_TIMEOUT ? Timeout : Failure;
}


std::string CgiHandler::content_type() {
    std::string content_type;

    if (this->media_type_.is_err()) {
        return "text/html";
    }

    content_type = this->media_type_.type();
    if (!this->media_type_.subtype().empty()) {
        content_type.append("/");
        content_type.append(this->media_type_.subtype());
    }
    return content_type;
}


std::string CgiHandler::location() { return this->location_; }


Result<StatusCode, ProcResult> parse_status_line(const std::string &field_value) {
    int code;
    std::string reason_prase;
    ProcResult parse_result = HttpMessageParser::split_status_code_and_reason_phrase(field_value,
                                                                                     &code,
                                                                                     &reason_prase);
    if (parse_result == Failure) {
        return Result<StatusCode, ProcResult>::err(Failure);
    }

    Result<StatusCode, ProcResult> convert_result = HttpMessageParser::convert_to_enum(code);
    if (convert_result.is_err()) {
        return Result<StatusCode, ProcResult>::err(Failure);
    }
    return Result<StatusCode, ProcResult>::ok(convert_result.ok_value());
}


/*
 Location = URI-reference
 https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.2
 */
StatusCode CgiHandler::parse_document_response() {
    StatusCode tmp_status = StatusInit;
    std::string tmp_location;
    MediaType tmp_content_type;
    int content_type_cnt = 0;
    while (true) {
        Result<std::string, ProcResult> line_result = pop_line_from_buf();
        if (line_result.is_err()) {
            return InternalServerError;  // no line in buf
        }
        std::string field_line = line_result.ok_value();
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
        if (field_value.empty()) {
            return InternalServerError;
        }
        field_name = StringHandler::to_lower(field_name);
        if (field_name == std::string(CONTENT_TYPE)) {
            if (1 < ++content_type_cnt) {  // duplicated
                return InternalServerError;
            }
            tmp_content_type = MediaType(field_value);
            if (tmp_content_type.is_err()) {  // parse error
                return InternalServerError;
            }
        } else if (field_name == std::string(LOCATION)) {
            if (!tmp_location.empty()) {  // duplicated
                return InternalServerError;
            }
            if (HttpMessageParser::is_uri_ref(field_value)) {
                tmp_location = field_value;
            } else {
                return InternalServerError;
            }
        } else if (field_name == "status") {
            if (tmp_status != StatusInit) {  // duplicated
                return InternalServerError;
            }
            Result<StatusCode, ProcResult> status_result = parse_status_line(field_value);
            if (status_result.is_err()) {
                return InternalServerError;
            }
            tmp_status = status_result.ok_value();
        }
    }

    if (HttpMessageParser::is_redirection_status(tmp_status) && !tmp_location.empty()) {
        this->location_ = tmp_location;
        this->cgi_status_ = tmp_status;
        return this->cgi_status_;
    }
    if (tmp_content_type.is_ok()) {
        this->media_type_ = tmp_content_type;
        this->cgi_status_ = (tmp_status == StatusInit) ? StatusOk : tmp_status;
        return this->cgi_status_;
    }
    if (content_type_cnt == 0) {
        this->cgi_status_ = (tmp_status == StatusInit) ? StatusOk : tmp_status;
        return this->cgi_status_;
    }
    return InternalServerError;
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
    std::string line = result.ok_value();
    HttpRequest::trim(&this->recv_buf_, next_line);

    std::string debug_buf(this->recv_buf_.begin(), this->recv_buf_.end());
    // DEBUG_SERVER_PRINT("buf[%s]", debug_buf.c_str());
    return Result<std::string, ProcResult>::ok(line);
}


ProcResult connect_from_parent_fd_to_stdin(int from_parant[2]) {
    errno = 0;
    if (close(from_parant[WRITE]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }
    errno = 0;
    if (dup2(from_parant[READ], STDIN_FILENO) == DUP_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }
    errno = 0;
    if (close(from_parant[READ]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }
    return Success;
}


ProcResult connect_to_parent_fd_to_stdout(int to_parent[2]) {
    errno = 0;
    if (close(to_parent[READ]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }
    errno = 0;
    if (dup2(to_parent[WRITE], STDOUT_FILENO) == DUP_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }

    errno = 0;
    if (close(to_parent[WRITE]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        return Failure;
    }
    return Success;
}


ProcResult CgiHandler::handle_child_fd(int from_parant[2], int to_parent[2]) {
    if (connect_from_parent_fd_to_stdin(from_parant) == Failure) {
        return Failure;
    }
    if (connect_to_parent_fd_to_stdout(to_parent) == Failure) {
        return Failure;
    }
    return Success;
}


int CgiHandler::exec_script_in_child(int from_parant[2],
                                     int to_parent[2],
                                     const std::string &file_path) {
    DEBUG_PRINT(CYAN, "    cgi(child) 1");
    if (handle_child_fd(from_parant, to_parent) == Failure) {
        close_socket_pairs(from_parant);
        close_socket_pairs(to_parent);
        DEBUG_PRINT(CYAN, "    cgi(child) 2 error");
        return EXIT_FAILURE;
    }
    // DEBUG_PRINT(RED, "-------------- error occurred --------------");
    // return EXIT_FAILURE;

    char **argv = create_argv(file_path);
    if (!argv) {
        DEBUG_PRINT(CYAN, "    cgi(child) 3 argv error");
        close_socket_pairs(from_parant);
        close_socket_pairs(to_parent);
        return EXIT_FAILURE;
    }
    char **envp = create_envp(this->params_);
    if (!envp) {
        delete_char_double_ptr(argv);
        close_socket_pairs(from_parant);
        close_socket_pairs(to_parent);
        DEBUG_PRINT(CYAN, "    cgi(child) 4 envp error");
        return EXIT_FAILURE;
    }

    DEBUG_PRINT(CYAN, "    cgi(child) 5, argv[0]:%s", argv[0]);
    errno = 0;
    if (execve(argv[0],
               static_cast<char *const *>(argv),
               static_cast<char *const *>(envp)) == EXECVE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp -> log?
        DEBUG_PRINT(CYAN, "    cgi(child) 6 execve error");
    }
    DEBUG_PRINT(CYAN, "    cgi(child) 7 error");
    delete_char_double_ptr(envp);
    delete_char_double_ptr(argv);
    close_socket_pairs(from_parant);
    close_socket_pairs(to_parent);
    return EXIT_FAILURE;
}


ProcResult CgiHandler::handle_parent_fd(int to_child[2], int from_child[2]) {
    errno = 0;
    if (close(to_child[READ]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: logging
        return Failure;
    }
    errno = 0;
    if (close(from_child[WRITE]) == CLOSE_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: logging
        return Failure;
    }

    Result<int, std::string> result;
    result = Socket::set_fd_to_nonblock(to_child[WRITE]);
    if (result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR(result.err_value());
        std::cerr << "to_child[WRITE]: fd=" << to_child[WRITE] << ": " << error_msg << std::endl;
        return Failure;
    }
    result = Socket::set_fd_to_nonblock(from_child[READ]);
    if (result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR(result.err_value());
        std::cerr << "from_child[READ]: fd="<< from_child[READ] << ": " << error_msg << std::endl;
        return Failure;
    }

    set_cgi_write_fd(to_child[WRITE]);
    set_cgi_read_fd(from_child[READ]);
    return Success;
}


void CgiHandler::set_cgi_params(const CgiParams &params) {
    this->params_ = params;
}


ProcResult CgiHandler::create_socket_pair(int to_child[2], int from_child[2]) {
    Result<int, std::string> socketpair_result;

    socketpair_result = create_socketpair(to_child);
    if (socketpair_result.is_err()) {
        const std::string error_msg = socketpair_result.err_value();
        std::cerr << "[Error] socketpair: " << error_msg << std::endl;  // todo: tmp
        return Failure;  // todo: tmp
    }

    socketpair_result = create_socketpair(from_child);
    if (socketpair_result.is_err()) {
        const std::string error_msg = socketpair_result.err_value();
        std::cerr << "[Error] socketpair: " << error_msg << std::endl;  // todo: tmp
        return Failure;  // todo: tmp
    }
    return Success;
}


void CgiHandler::close_socket_pairs(int fds[2]) {
    if (fds[READ] != INIT_FD) {
        close(fds[READ]);
        fds[READ] = INIT_FD;
    }
    if (fds[WRITE] != INIT_FD) {
        close(fds[WRITE]);
        fds[WRITE] = INIT_FD;
    }
}


ProcResult CgiHandler::exec_script(const std::string &file_path) {
    int to_child[2], from_child[2];

    to_child[READ] = INIT_FD;
    to_child[WRITE] = INIT_FD;
    from_child[READ] = INIT_FD;
    from_child[WRITE] = INIT_FD;

    DEBUG_PRINT(CYAN, "   exec_script 1");
    if (create_socket_pair(to_child, from_child) == Failure) {
        close_socket_pairs(to_child);
        close_socket_pairs(from_child);
        return Failure;
    }
    DEBUG_PRINT(CYAN, "   exec_script 2");

    errno = 0;
    pid_t pid = fork();
    if (pid == FORK_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << error_msg << std::endl;  // todo: tmp
        close_socket_pairs(to_child);
        close_socket_pairs(from_child);
        return Failure;  // todo: tmp
    }

    DEBUG_PRINT(CYAN, "   exec_script 3");
    if (pid == CHILD_PROC) {
        DEBUG_PRINT(CYAN, "   exec_script 4 child(pid: %d)", pid);
        std::exit(exec_script_in_child(to_child, from_child, file_path));
    } else {
        DEBUG_PRINT(CYAN, "   exec_script 4 parent(pid: %d)", pid);
        if (handle_parent_fd(to_child, from_child) == Failure) {
            close_socket_pairs(to_child);
            close_socket_pairs(from_child);
            return Failure;
        }
        set_cgi_pid(pid);
        set_timeout_limit();
        DEBUG_PRINT(CYAN, "   exec_script 5(write_fd: %d, read_fd: %d, pid: %d) start_time: %zu, limit: %zu",
                    write_fd(), read_fd(), pid, std::time(NULL), timeout_limit());
        return Success;
    }
}


bool CgiHandler::is_processing() const {
    return this->pid() != INIT_PID;
}


bool CgiHandler::is_processing(int *status, int flag) {
    DEBUG_PRINT(YELLOW, "  [is_cgi_processing]: pid: %d at %zu", pid(), std::time(NULL));
    int child_status;

    errno = 0;
    pid_t wait_result = waitpid(this->pid(), &child_status, flag);
    int tmp_err = errno;
    DEBUG_PRINT(YELLOW, "   wait_result: %d, errno: %d (ECHILD: %d)", wait_result, tmp_err, ECHILD);
    if (wait_result == PROCESSING) {
        DEBUG_PRINT(YELLOW, "  waitpid=0 -> continue");
        return true;
    }
    // if (wait_result == WAIT_ERROR && tmp_err != ECHILD) {
    //     DEBUG_PRINT(YELLOW, "  waitpid=-1&&errno != ECHILD-> continue");
    //     return true;
    // }
    if (!status) {
        return false;
    }
    if (0 < wait_result) {
        if (WIFSIGNALED(child_status)) {
            int term_sig = WTERMSIG(child_status);
            if (term_sig == SIGKILL) {
                *status = PROCESS_TIMEOUT;
            } else {
                *status = EXIT_FAILURE;
            }
            DEBUG_PRINT(YELLOW, "    Child terminated by signal: %d, status: %d", term_sig, *status);
        } else {
            *status = WEXITSTATUS(child_status);
            DEBUG_PRINT(YELLOW, "  [is_cgi_processing]: status: %d", *status);
        }
    }
    DEBUG_PRINT(YELLOW, "  [is_cgi_processing]: pid set to init -> next");
    set_cgi_pid(INIT_PID);
    return false;
}


void CgiHandler::set_cgi_read_fd(int read_fd) { this->cgi_read_fd_ = read_fd; }


void CgiHandler::set_cgi_write_fd(int write_fd) { this->cgi_write_fd_ = write_fd; }


void CgiHandler::set_cgi_pid(pid_t pid) {
    DEBUG_PRINT(YELLOW, "cgi set_pid  %d -> %d", this->pid(), pid);
    this->cgi_pid_ = pid;
}

void CgiHandler::set_timeout_limit() {
    this->timeout_limit_ = std::time(NULL) + this->timeout_duration_sec();
    DEBUG_PRINT(YELLOW, "cgi set_timeout_limit: %zu, duration: %zu sec", this->timeout_limit(), this->timeout_duration_sec());
}


void CgiHandler::clear_recv_buf() {
    this->recv_buf_.clear();
}


int CgiHandler::read_fd() const { return this->cgi_read_fd_; }
int CgiHandler::write_fd() const { return this->cgi_write_fd_; }
pid_t CgiHandler::pid() const { return this->cgi_pid_; }
StatusCode CgiHandler::cgi_status_code() const { return this->cgi_status_; }
time_t CgiHandler::timeout_limit() const { return this->timeout_limit_; }
time_t CgiHandler::timeout_duration_sec() const { return this->timeout_duration_sec_; }
const std::vector<unsigned char> &CgiHandler::cgi_body() const { return this->recv_buf_; }

void CgiHandler::set_timeout_duration_sec(time_t timeout_sec) {
    DEBUG_PRINT(WHITE, "set_timeout_duration");
    if (ConfigParser::is_valid_cgi_timeout(timeout_sec)) {
        DEBUG_PRINT(WHITE, " cgi set_timeout_duration [%zu]->[%zu]sec", this->timeout_duration_sec_, timeout_sec);
        this->timeout_duration_sec_ = timeout_sec;
    }
}

bool CgiHandler::is_process_timeout() const {
    time_t current_time = std::time(NULL);
    return (this->timeout_limit() < current_time);
}
