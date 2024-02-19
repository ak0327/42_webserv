#include <sys/socket.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

/* sub funcs; unnamed namespace */
namespace {

// field-line = field-name ":" OWS field-value OWS
//              ^head       ^colon
Result<std::string, int> parse_field_name(const std::string &field_line,
										  std::size_t *pos) {
	std::size_t head_pos, colon_pos, len;
	std::string field_name;

	if (!pos) { return Result<std::string, int>::err(ERR); }

	head_pos = 0;
	colon_pos = field_line.find(':', head_pos);
	if (colon_pos == std::string::npos || colon_pos <= head_pos) {
		return Result<std::string, int>::err(ERR);
	}
	len = colon_pos - head_pos;

	field_name = field_line.substr(head_pos, len);
	*pos += len;
	return Result<std::string, int>::ok(field_name);
}

void skip_whitespace(const std::string &str, std::size_t *pos) {
	if (!pos) { return; }

	while (HttpMessageParser::is_whitespace(str[*pos])) {
		(*pos)++;
	}
}

void skip_non_whitespace(const std::string &str, std::size_t *pos) {
	if (!pos) { return; }

	while (str[*pos] && !HttpMessageParser::is_whitespace(str[*pos])) {
		(*pos)++;
	}
}

// field-line CRLF
// field-line = field-name ":" OWS field-value OWS
//                                 ^head
Result<std::string, int> parse_field_value(const std::string &field_line,
										   std::size_t *head_pos) {
	std::size_t len, ws_len;
	std::string field_value;

	if (!head_pos) { return Result<std::string, int>::err(ERR); }

	len = 0;
	while (field_line[*head_pos + len]) {
		skip_non_whitespace(&field_line[*head_pos], &len);

		ws_len = 0;
		skip_whitespace(&field_line[*head_pos + len], &ws_len);

		if (field_line[*head_pos + len + ws_len] == '\0') {
			break;
		}
		len += ws_len;
	}

	field_value = field_line.substr(*head_pos, len);
	*head_pos += len;
	return Result<std::string, int>::ok(field_value);
}

void restore_crlf_to_ss(std::stringstream *ss) {
	std::streampos current_pos = ss->tellg();
	ss->seekg(current_pos - std::streamoff(std::string(CRLF).length()));
}

Result<std::string, int> get_field_line_by_remove_cr(const std::string &line_end_with_cr) {
	std::string field_line;

	if (!HttpMessageParser::is_end_with_cr(line_end_with_cr)) {
		return Result<std::string, int>::err(ERR);
	}
	field_line = line_end_with_cr.substr(0, line_end_with_cr.length() - 1);
	return Result<std::string, int>::ok(field_line);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
/* constructor, destructor */

HttpRequest::HttpRequest() : status_code_(STATUS_OK) {
    init_field_name_parser();
    init_field_name_counter();
}

HttpRequest::HttpRequest(const std::string &input) : status_code_(STATUS_OK) {
	init_field_name_parser();
	init_field_name_counter();
	this->status_code_ = parse_and_validate_http_request(input);
}

HttpRequest::~HttpRequest()
{
	std::map<std::string, FieldValueBase*>::iterator itr;

	itr = this->request_header_fields_.begin();
	while (itr != this->request_header_fields_.end()) {
		delete itr->second;
		++itr;
	}
}

void HttpRequest::clear_field_values_of(const std::string &field_name) {
	if (is_valid_field_name_registered(field_name)) {
		delete this->request_header_fields_[field_name];
		this->request_header_fields_.erase(field_name);
	}
}


////////////////////////////////////////////////////////////////////////////////


ssize_t HttpRequest::recv(int fd, void *buf, std::size_t bufsize) {
    ssize_t recv_size;

    errno = 0;
    recv_size = ::recv(fd, buf, bufsize, FLAG_NONE);
    int tmp_errno = errno;
    DEBUG_SERVER_PRINT("    recv_size: %zd", recv_size);
    if (recv_size == RECV_COMPLETED) {
        return RECV_COMPLETED;
    }
    if (recv_size == RECV_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(tmp_errno);
        DEBUG_SERVER_PRINT("%s", error_msg.c_str());
        // return Result<std::size_t, std::string>::err(error_info);
        return RECV_COMPLETED;  // non-blocking -> recv completed
    }
    return recv_size;
}


std::size_t HttpRequest::recv_all_data(int fd,
                                       std::vector<unsigned char> *buf,
                                       std::size_t max_size) {
    unsigned char recv_buf[BUFSIZ];
    ssize_t recv_size;

    if (!buf) {
        return 0;
    }
    std::size_t total_size = buf->size();

    DEBUG_SERVER_PRINT("    recv start");

    while (true) {
        recv_size = HttpRequest::recv(fd, recv_buf, BUFSIZ);
        DEBUG_SERVER_PRINT("    recv_size: %zd", recv_size);
        if (recv_size == RECV_COMPLETED) {
            break;
        }

        total_size += recv_size;
        buf->insert(buf->end(), recv_buf, recv_buf + recv_size);
        if (max_size < total_size) {
            DEBUG_SERVER_PRINT("     recv_size exceeded max_body_size");
            break;
        }
    }
    std::string recv_body(buf->begin(), buf->end());
    DEBUG_SERVER_PRINT("    recv_msg[%s]", recv_body.c_str());
    DEBUG_SERVER_PRINT("    recv end");
    return total_size;
}


std::size_t HttpRequest::recv_all_data(int fd,
                                       std::vector<unsigned char> *save_buf) {
    return recv_all_data(fd, save_buf, std::numeric_limits<std::size_t>::max());
}


bool HttpRequest::is_crlf_in_buf(const unsigned char buf[], std::size_t size) {
    if (size < 2) {
        return false;
    }
    for (std::size_t i = 0; i < size - 1; ++i) {
        if (buf[i] == CR && buf[i + 1] == LF) {
            return true;
        }
    }
    return false;
}


// while CRLF CRLF
Result<int, std::string> HttpRequest::recv_until_empty_line(int fd) {
    unsigned char recv_buf[BUFSIZ];
    std::vector<unsigned char>::const_iterator empty_pos, find_begin;
    ssize_t recv_size;
    DEBUG_PRINT(YELLOW, "recv_until_empty_line");
    while (true) {
        recv_size = HttpRequest::recv(fd, recv_buf, BUFSIZ);
        DEBUG_PRINT(YELLOW, " recv_size: %zd", recv_size);
        if (recv_size == RECV_COMPLETED) {
            break;
        }

        std::size_t old_size = this->buf_.size();
        this->buf_.insert(this->buf_.end(), recv_buf, recv_buf + recv_size);
        std::size_t shift = (old_size < 4) ? recv_size + old_size : recv_size + 3;
        find_begin = this->buf_.end() - shift;
        HttpRequest::find_empty(this->buf_, find_begin, &empty_pos);
        if (empty_pos != this->buf_.end()) {
            break;
        }
    }

    std::string recv_msg(this->buf_.begin(), this->buf_.end());
    DEBUG_PRINT(YELLOW, " recv_msg[%s]", recv_msg.c_str());
    return Result<int, std::string>::ok(OK);
}


// while CRLF
Result<int, std::string> HttpRequest::recv_start_line(int fd) {
    unsigned char recv_buf[BUFSIZ];
    ssize_t recv_size;
    bool is_prev_end_with_cr = false;

    while (true) {
        recv_size = HttpRequest::recv(fd, recv_buf, BUFSIZ);
        if (recv_size == RECV_COMPLETED) {
            break;
        }

        this->buf_.insert(this->buf_.end(), recv_buf, recv_buf + recv_size);
        if (is_crlf_in_buf(recv_buf, recv_size)) {
            break;
        }
        if (is_prev_end_with_cr && recv_buf[0] == LF) {
            break;
        }
        is_prev_end_with_cr = (recv_buf[recv_size - 1] == CR);
    }
    return Result<int, std::string>::ok(OK);
}


// string CR LF
//         ^return
void HttpRequest::find_crlf(const std::vector<unsigned char> &data,
                            std::vector<unsigned char>::const_iterator start,
                            std::vector<unsigned char>::const_iterator *cr) {
    if (!cr) {
        return;
    }
    std::vector<unsigned char>::const_iterator itr = start;
    while (itr != data.end() && itr + 1 != data.end()) {
        if (*itr == CR && *(itr + 1) == LF) {
            *cr = itr;
            return;
        }
        ++itr;
    }
    *cr = data.end();
}


// line CRLF CRLF line
//      ^return
void HttpRequest::find_empty(const std::vector<unsigned char> &data,
                            std::vector<unsigned char>::const_iterator start,
                            std::vector<unsigned char>::const_iterator *ret) {
    const std::size_t CRLF_LEN = 2;
    if (!ret) {
        return;
    }
    std::vector<unsigned char>::const_iterator pos, crlf1, crlf2;
    pos = start;
    while (pos != data.end()) {
        find_crlf(data, pos, &crlf1);
        if (crlf1 == data.end()) {
            break;
        }
        find_crlf(data, crlf1 + CRLF_LEN, &crlf2);
        if (crlf2 == data.end()) {
            break;
        }
        if (crlf1 + CRLF_LEN == crlf2) {
            *ret = crlf1;
            return;
        }
        pos = crlf1 + CRLF_LEN;
    }
    *ret = data.end();
}


// line CRLF next_line
// ^^^^      ^ret
Result<std::string, std::string> HttpRequest::get_line(const std::vector<unsigned char> &data,
                                                       std::vector<unsigned char>::const_iterator start,
                                                       std::vector<unsigned char>::const_iterator *ret) {
    if (!ret) {
        return Result<std::string, std::string>::err("fatal error");
    }

    std::vector<unsigned char>::const_iterator cr;
    HttpRequest::find_crlf(data, start, &cr);
    if (cr == data.end()) {
        *ret = data.end();
        return Result<std::string, std::string>::err("line invalid");
    }

    std::string line(start, cr);
    *ret = cr + 2;
    return Result<std::string, std::string>::ok(line);
}


void HttpRequest::trim(std::vector<unsigned char> *buf,
                       std::vector<unsigned char>::const_iterator start) {
    if (!buf || buf->empty() || start == buf->begin()) {
        return;
    }
    typedef std::vector<unsigned char>::iterator itr;
    typedef std::vector<unsigned char>::const_iterator const_itr;

    std::ptrdiff_t offset = std::distance((const_itr)buf->begin(), start);
    itr non_const_start = buf->begin() + offset;

    buf->erase(buf->begin(), non_const_start);
}


Result<int, StatusCode> HttpRequest::recv_request_line_and_header(int fd) {
    Result<int, std::string> recv_result = recv_until_empty_line(fd);
    if (recv_result.is_err()) {
        const std::string error_msg = recv_result.get_err_value();
        DEBUG_SERVER_PRINT("error: %s", error_msg.c_str());
        return Result<int, StatusCode>::err(STATUS_SERVER_ERROR);
    }
    return Result<int, StatusCode>::ok(OK);
}


// start-line CRLF
Result<int, StatusCode> HttpRequest::parse_request_line() {
    std::vector<unsigned char>::const_iterator next_start;
    Result<std::string, std::string> get_line_result;
    get_line_result = get_line(this->buf_, this->buf_.begin(), &next_start);
    if (get_line_result.is_err()) {
        return Result<int, int>::err(STATUS_SERVER_ERROR);
    }
    std::string start_line = get_line_result.get_ok_value();
    DEBUG_SERVER_PRINT("     start_line[%s]", start_line.c_str());

    HttpRequest::trim(&this->buf_, next_start);

    Result<int, int> request_line_result = this->request_line_.parse_and_validate(start_line);
    if (request_line_result.is_err()) {
        return Result<int, int>::err(STATUS_BAD_REQUEST);
    }
    return Result<int, int>::ok(OK);
}


Result<int, StatusCode> HttpRequest::parse_header() {
    std::vector<unsigned char>::const_iterator header_end;
    HttpRequest::find_empty(this->buf_, this->buf_.begin(), &header_end);
    std::size_t headers_len = header_end - this->buf_.begin();
    std::string request_headers(reinterpret_cast<const char*>(&buf_[0]), headers_len);

    const std::size_t EMPTY_LINE_LEN = 4;
    std::vector<unsigned char>::const_iterator body_start = header_end + EMPTY_LINE_LEN;
    HttpRequest::trim(&this->buf_, body_start);

    Result<int, StatusCode> parse_result = parse_and_validate_field_lines(request_headers);
    if (parse_result.is_err()) {
        return Result<int, StatusCode>::ok(parse_result.is_err());
    }
    return Result<int, StatusCode>::ok(OK);
}


Result<int, int> HttpRequest::recv_body(int fd, std::size_t max_body_size) {
    size_t body_size = recv_all_data(fd, &this->buf_, max_body_size);
    if (max_body_size < body_size) {
        return Result<int, StatusCode>::err(REQUEST_ENTITY_TOO_LARGE);
    }
    std::string body(this->buf_.begin(), this->buf_.end());
    DEBUG_SERVER_PRINT("     recv_body:[%s]", body.c_str());
    return Result<int, StatusCode>::ok(OK);
}


Result<HostPortPair, StatusCode> HttpRequest::get_server_info() {
    Result<std::map<std::string, std::string>, int> result = get_host();
    if (result.is_err()) {
        return Result<HostPortPair, int>::err(STATUS_BAD_REQUEST);  // 400 Bad Request
    }
    std::map<std::string, std::string> host = result.get_ok_value();
    HostPortPair pair = std::make_pair(host[URI_HOST], host[PORT]);
    return Result<HostPortPair, int>::ok(pair);
}


////////////////////////////////////////////////////////////////////////////////
/* parse and validate http_request */

/*
 HTTP-message
	= start-line CRLF
	  *( field-line CRLF )
	  CRLF
	  [ message-body ]
 */
int HttpRequest::parse_and_validate_http_request(const std::string &input) {
	std::stringstream	ss(input);
	std::string 		line;


    // start-line CRLF
	std::getline(ss, line, LF);
    if (line.empty() || line[line.size() - 1] != CR) {
        return STATUS_BAD_REQUEST;
    }
    line.erase(line.size() - 1);
    Result<int, int> request_line_result = this->request_line_.parse_and_validate(line);
	if (request_line_result.is_err()) {
		return STATUS_BAD_REQUEST;
	}

	// *( field-line CRLF )
	try {
        Result<int, int> field_line_result = parse_and_validate_field_lines(&ss);

        if (field_line_result.is_err()) {
            if (field_line_result.get_err_value() == STATUS_SERVER_ERROR) {
                return STATUS_SERVER_ERROR;
            }
            return STATUS_BAD_REQUEST;
        }
	} catch (const std::bad_alloc &e) {
		return STATUS_SERVER_ERROR;
	}

	// CRLF
	std::getline(ss, line, LF);
	if (line != std::string(1, CR)) {
		return STATUS_BAD_REQUEST;
	}

	// [ message-body ]
	message_body_ = parse_message_body(&ss);
	return STATUS_OK;
}

////////////////////////////////////////////////////////////////////////////////
/* field-line parse and validate */

/*
 field-line CRLF
  v getline
 field-line CR

 field-line = field-name ":" OWS field-value OWS
 */
Result<int, StatusCode> HttpRequest::parse_and_validate_field_lines(std::stringstream *ss) {
	while (true) {
        std::string	line_end_with_cr;
		std::getline(*ss, line_end_with_cr, LF);
		if (ss->eof()) {
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
		if (HttpMessageParser::is_header_body_separator(line_end_with_cr)) {
			restore_crlf_to_ss(ss);
			break;
		}

        Result<std::string, int> field_line_result = get_field_line_by_remove_cr(line_end_with_cr);
		if (field_line_result.is_err()) {
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
		std::string field_line = field_line_result.get_ok_value();

        std::string	field_name, field_value;
        Result<int, int> parse_result = parse_field_line(field_line, &field_name, &field_value);
		if (parse_result.is_err()) {
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}

		if (!HttpMessageParser::is_valid_field_name_syntax(field_name)
			|| !HttpMessageParser::is_valid_field_value_syntax(field_value)) {
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}

		field_name = StringHandler::to_lower(field_name);
		if (is_field_name_supported_parsing(field_name)) {
			increment_field_name_counter(field_name);

			parse_result = (this->*field_value_parser_[field_name])(field_name, field_value);
			if (parse_result.is_err()) {
				return Result<int, int>::err(parse_result.get_err_value());  // todo: parse error -> status
			}
			continue;
		}
	}

	// todo: validate field_names, such as 'must' header,...
	if (!is_valid_field_name_registered(std::string(HOST))) {
		// std::cout << MAGENTA << "!is valid field name registered" << RESET << std::endl;
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	return Result<int, int>::ok(OK);
}


Result<int, StatusCode> HttpRequest::parse_and_validate_field_lines(const std::string &request_headers) {
    std::stringstream ss(request_headers);
    try {
        Result<int, StatusCode> field_line_result = parse_and_validate_field_lines(&ss);
        if (field_line_result.is_err()) {
            return Result<int, StatusCode>::err(field_line_result.get_err_value());
        }
        return Result<int, StatusCode>::ok(OK);
    } catch (const std::bad_alloc &e) {
        return Result<int, StatusCode>::err(STATUS_SERVER_ERROR);
    }
}


// field-line = field-name ":" OWS field-value OWS
Result<int, int> HttpRequest::parse_field_line(const std::string &field_line,
								  std::string *ret_field_name,
								  std::string *ret_field_value) {
	if (!ret_field_name || !ret_field_value) { return Result<int, int>::err(ERR); }

	// field-name
	std::size_t pos = 0;
    Result<std::string, int> field_name_result = parse_field_name(field_line, &pos);
	if (field_name_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	std::string field_name = field_name_result.get_ok_value();

	// ":"
	if (field_line[pos] != ':') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}

	// field-value
    Result<std::string, int> field_value_result = parse_field_value(field_line, &pos);
	if (field_value_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
    std::string field_value = field_value_result.get_ok_value();

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}
	if (field_line[pos] != '\0') {
		return Result<int, int>::err(ERR);
	}

	*ret_field_name = field_name;
	*ret_field_value = field_value;
	return Result<int, int>::ok(OK);
}


// [ message-body ]
std::string HttpRequest::parse_message_body(std::stringstream *ss) {
	return ss->str();
}


bool HttpRequest::is_valid_field_name_registered(const std::string &field_name) {
	return this->request_header_fields_.count(field_name) != 0;
}


// call this function after increment
bool HttpRequest::is_field_name_repeated_in_request(const std::string &field_name) {
	return SINGLE_OCCURRENCE_LIMIT < this->field_name_counter_[field_name];
}


void HttpRequest::increment_field_name_counter(const std::string &field_name) {
	this->field_name_counter_[field_name]++;
}


bool HttpRequest::is_field_name_supported_parsing(const std::string &field_name) {
	if (HttpMessageParser::is_ignore_field_name(field_name)) {
		return false;
	}
	return this->field_value_parser_.count(field_name) != 0;
}


////////////////////////////////////////////////////////////////////////////////

void HttpRequest::init_field_name_counter() {
	std::vector<std::string>::const_iterator itr;
	for (itr = FIELD_NAMES.begin(); itr != FIELD_NAMES.end(); ++itr) {
		this->field_name_counter_[*itr] = COUNTER_INIT;
	}
}


void HttpRequest::init_field_name_parser() {
	std::map<std::string, func_ptr> map;

	map[std::string(ACCEPT)] = &HttpRequest::set_accept;
	map[std::string(ACCEPT_ENCODING)] = &HttpRequest::set_accept_encoding;
	map[std::string(ACCEPT_LANGUAGE)] = &HttpRequest::set_accept_language;
	map[std::string(ACCESS_CONTROL_REQUEST_HEADERS)] = &HttpRequest::set_access_control_request_headers;
	map[std::string(ACCESS_CONTROL_REQUEST_METHOD)] = &HttpRequest::set_access_control_request_method;
	map[std::string(ALT_USED)] = &HttpRequest::set_alt_used;
	map[std::string(AUTHORIZATION)] = &HttpRequest::set_authorization;
	map[std::string(CACHE_CONTROL)] =  &HttpRequest::set_cache_control;
	map[std::string(CONNECTION)] = &HttpRequest::set_connection;
	map[std::string(CONTENT_DISPOSITION)] = &HttpRequest::set_content_disposition;
	map[std::string(CONTENT_ENCODING)] = &HttpRequest::set_content_encoding;
	map[std::string(CONTENT_LANGUAGE)] = &HttpRequest::set_content_language;
	map[std::string(CONTENT_LENGTH)] = &HttpRequest::set_content_length;
	map[std::string(CONTENT_LOCATION)] = &HttpRequest::set_content_location;
	map[std::string(CONTENT_TYPE)] = &HttpRequest::set_content_type;
	map[std::string(COOKIE)] = &HttpRequest::set_cookie;
	map[std::string(DATE)] = &HttpRequest::set_date;
	map[std::string(EXPECT)] = &HttpRequest::set_expect;
	map[std::string(FORWARDED)] = &HttpRequest::set_forwarded;
	map[std::string(FROM)] = &HttpRequest::set_from;
	map[std::string(HOST)] = &HttpRequest::set_host;
	map[std::string(IF_MATCH)] = &HttpRequest::set_if_match;
	map[std::string(IF_MODIFIED_SINCE)] = &HttpRequest::set_if_modified_since;
	map[std::string(IF_NONE_MATCH)] = &HttpRequest::set_if_none_match;
	map[std::string(IF_RANGE)] = &HttpRequest::set_if_range;
	map[std::string(IF_UNMODIFIED_SINCE)] = &HttpRequest::set_if_unmodified_since;
	map[std::string(KEEP_ALIVE)] = &HttpRequest::set_keep_alive;
	map[std::string(LAST_MODIFIED)] = &HttpRequest::set_last_modified;
	map[std::string(LINK)] = &HttpRequest::set_link;
	map[std::string(MAX_FORWARDS)] = &HttpRequest::set_max_forwards;
	map[std::string(ORIGIN)] = &HttpRequest::set_origin;
	map[std::string(PROXY_AUTHORIZATION)] = &HttpRequest::set_proxy_authorization;
	map[std::string(RANGE)] = &HttpRequest::set_range;
	map[std::string(REFERER)] = &HttpRequest::set_referer;
	map[std::string(SEC_FETCH_DEST)] = &HttpRequest::set_sec_fetch_dest;
	map[std::string(SEC_FETCH_MODE)] = &HttpRequest::set_sec_fetch_mode;
	map[std::string(SEC_FETCH_SITE)] = &HttpRequest::set_sec_fetch_site;
	map[std::string(SEC_FETCH_USER)] = &HttpRequest::set_sec_fetch_user;
	map[std::string(SEC_PURPOSE)] = &HttpRequest::set_sec_purpose;
	map[std::string(SERVICE_WORKER_NAVIGATION_PRELOAD)] = &HttpRequest::set_service_worker_navigation_preload;
	map[std::string(TE)] = &HttpRequest::set_te;
	map[std::string(TRAILER)] = &HttpRequest::set_trailer;
	map[std::string(TRANSFER_ENCODING)] = &HttpRequest::set_transfer_encoding;
	map[std::string(UPGRADE)] = &HttpRequest::set_upgrade;
	map[std::string(UPGRADE_INSECURE_REQUESTS)] = &HttpRequest::set_upgrade_insecure_requests;
	map[std::string(USER_AGENT)] = &HttpRequest::set_user_agent;
	map[std::string(VIA)] = &HttpRequest::set_via;

	this->field_value_parser_ = map;
}


std::string HttpRequest::get_method() const {
	return this->request_line_.get_method();
}


std::string HttpRequest::get_request_target() const {
	return this->request_line_.get_request_target();
}


std::string HttpRequest::get_http_version() const {
	return this->request_line_.get_http_version();
}


bool HttpRequest::is_buf_empty() const {
    return this->buf_.empty();
}


FieldValueBase * HttpRequest::get_field_values(const std::string &key) const {
    std::map<std::string, FieldValueBase *>::const_iterator itr;

    itr = this->request_header_fields_.find(key);
    if (itr == this->request_header_fields_.end()) {
        return NULL;
    }
	return itr->second;
}


std::map<std::string, FieldValueBase*> HttpRequest::get_request_header_fields(void) {
	return this->request_header_fields_;
}


int	HttpRequest::get_status_code() const {
	return this->status_code_;
}


void HttpRequest::set_status_code(int new_code) {
    this->status_code_ = new_code;
}


Result<std::map<std::string, std::string>, int> HttpRequest::get_host() const {
    FieldValueBase *field_values = get_field_values(HOST);
    if (!field_values) {
        return Result<std::map<std::string, std::string>, int>::err(ERR);
    }
    MapFieldValues *map_field_values = dynamic_cast<MapFieldValues *>(field_values);
    if (!map_field_values) {
        return Result<std::map<std::string, std::string>, int>::err(ERR);
    }

    std::map<std::string, std::string> host = map_field_values->get_value_map();
    return Result<std::map<std::string, std::string>, int>::ok(host);
}


#ifdef ECHO
const std::vector<unsigned char> &HttpRequest::get_buf() const {
    return this->buf_;
}
#endif
