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
#include "Socket.hpp"
#include "StringHandler.hpp"
#include "MediaType.hpp"

/* sub funcs; unnamed namespace */
namespace {

// field-line = field-name ":" OWS field-value OWS
//              ^head       ^colon
Result<std::string, int> parse_field_name(const std::string &field_line,
										  std::size_t *pos) {
	std::size_t head_pos, colon_pos, len;
	std::string field_name;

	if (!pos) { return Result<std::string, int>::err(BadRequest); }

	head_pos = 0;
	colon_pos = field_line.find(':', head_pos);
	if (colon_pos == std::string::npos || colon_pos <= head_pos) {
		return Result<std::string, int>::err(BadRequest);
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
Result<std::string, StatusCode> parse_field_value(const std::string &field_line,
										   std::size_t *head_pos) {
	std::size_t len, ws_len;
	std::string field_value;

	if (!head_pos) { return Result<std::string, StatusCode>::err(BadRequest); }

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
	return Result<std::string, StatusCode>::ok(field_value);
}

void restore_crlf_to_ss(std::stringstream *ss) {
	std::streampos current_pos = ss->tellg();
	ss->seekg(current_pos - std::streamoff(std::string(CRLF).length()));
}

Result<std::string, StatusCode> get_field_line_by_remove_cr(const std::string &line_end_with_cr) {
	std::string field_line;

	if (!HttpMessageParser::is_end_with_cr(line_end_with_cr)) {
		return Result<std::string, StatusCode>::err(BadRequest);
	}
	field_line = line_end_with_cr.substr(0, line_end_with_cr.length() - 1);
	return Result<std::string, StatusCode>::ok(field_line);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
/* constructor, destructor */

HttpRequest::HttpRequest()
    : phase_(ParsingRequestLine),
      status_code_(StatusOk),
      buf_(),
      request_body_(),
      field_value_parser_(),
      field_name_counter_(),
      request_max_body_size_(0) {
    init_field_name_parser();
    init_field_name_counter();
}

HttpRequest::HttpRequest(const std::string &input)  // for test
    : phase_(ParsingRequestLine),
      status_code_(StatusOk),
      buf_(),
      request_body_(),
      field_value_parser_(),
      field_name_counter_(),
      request_max_body_size_(0) {
	init_field_name_parser();
	init_field_name_counter();
	this->status_code_ = parse_and_validate_http_request(input);
}

HttpRequest::~HttpRequest() {
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


ssize_t HttpRequest::recv_to_buf(int fd) {
    return Socket::recv_to_buf(fd, &this->buf_);
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


// line CRLF next_line
// ^^^^      ^ret
Result<std::string, ProcResult> HttpRequest::get_line(const std::vector<unsigned char> &data,
                                                      std::vector<unsigned char>::const_iterator start,
                                                      std::vector<unsigned char>::const_iterator *ret) {
    if (!ret) {
        return Result<std::string, ProcResult>::err(FatalError);
    }

    std::vector<unsigned char>::const_iterator cr;
    HttpRequest::find_crlf(data, start, &cr);
    if (cr == data.end()) {
        *ret = data.end();
        return Result<std::string, ProcResult>::err(Failure);
    }

    std::string line(start, cr);
    *ret = cr + 2;
    return Result<std::string, ProcResult>::ok(line);
}


Result<std::string, ProcResult> HttpRequest::pop_line_from_buf(std::vector<unsigned char> *buf) {
    if (!buf) {
        return Result<std::string, ProcResult>::err(Failure);
    }

    std::vector<unsigned char>::const_iterator next_line;
    Result<std::string, ProcResult> result = get_line(*buf,
                                                      buf->begin(),
                                                      &next_line);
    if (result.is_err()) {
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string line = result.ok_value();
    trim(buf, next_line);

    std::string debug_buf(buf->begin(), buf->end());
    DEBUG_SERVER_PRINT("buf[%s]", debug_buf.c_str());
    return Result<std::string, ProcResult>::ok(line);
}


Result<std::string, ProcResult> HttpRequest::pop_line_from_buf() {
    return pop_line_from_buf(&this->buf_);
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


////////////////////////////////////////////////////////////////////////////////

// recv -> start_line -> header
// -> conf
// -> body
// recv -> body

Result<ProcResult, StatusCode> HttpRequest::parse_start_line_and_headers() {
    Result<ProcResult, StatusCode> result;
    StatusCode error_status_code;

    DEBUG_SERVER_PRINT("    parse start_line_and_headers 1");
    while (true) {
        DEBUG_SERVER_PRINT("    parse start_line_and_headers 2");
        Result<std::string, ProcResult> line_result = pop_line_from_buf();
        if (line_result.is_err()) {
            DEBUG_SERVER_PRINT("    parse start_line_and_headers -> continue");
            return Result<ProcResult, StatusCode>::ok(Continue);  // no line in buf -> recv
        }
        std::string line = line_result.ok_value();
        DEBUG_SERVER_PRINT("    parse start_line_and_headers 3 line[%s]", line.c_str());

        switch (this->phase_) {
            case ParsingRequestLine:
                DEBUG_SERVER_PRINT("    parse RequestLine");
                result = this->request_line_.parse_and_validate(line);
                if (result.is_err()) {
                    DEBUG_SERVER_PRINT("     parse RequestLine err");
                    error_status_code = result.err_value();
                    return Result<ProcResult, StatusCode>::err(error_status_code);  // todo: code
                }
                DEBUG_SERVER_PRINT("     parse RequestLine -> Header");
                this->phase_ = ParsingRequestHeaders;
                continue;

            case ParsingRequestHeaders:
                DEBUG_SERVER_PRINT("    parse Headers");
                if (line.empty()) {
                    this->phase_ = ParsingRequestBody;
                    DEBUG_SERVER_PRINT("     parse Headers -> body");
                    return Result<ProcResult, StatusCode>::ok(PrepareNextProc);  // conf -> parse body
                }
                result = parse_and_validate_field_line(line);
                if (result.is_err()) {
                    DEBUG_SERVER_PRINT("     parse Headers -> err");
                    error_status_code = result.err_value();
                    return Result<ProcResult, StatusCode>::err(error_status_code);  // todo: code
                }
                DEBUG_SERVER_PRINT("     parse Headers -> continue");
                continue;

            default:
                break;
        }
        break;
    }
    return Result<ProcResult, StatusCode>::ok(Success);
}


Result<ProcResult, StatusCode> HttpRequest::parse_body() {
    DEBUG_SERVER_PRINT("    ParseBody");

    Result<std::size_t, ProcResult> result = get_content_length();
    if (result.is_err()) {
        DEBUG_SERVER_PRINT("      ParseBody content-length not defined");
        if (this->buf_.empty()) {
            DEBUG_SERVER_PRINT("      ParseBody  recv body = 0 -> ok");
            return Result<ProcResult, StatusCode>::ok(Success);
        } else {
            DEBUG_SERVER_PRINT("      ParseBody  recv body != 0 -> err");
            this->buf_.clear();
            return Result<ProcResult, StatusCode>::err(BadRequest);
        }
    }

    std::size_t content_length = result.ok_value();
    DEBUG_SERVER_PRINT("      ParseBody content-length: %zu", content_length);

    if (this->request_max_body_size_ < content_length) {
        DEBUG_SERVER_PRINT("      ParseBody max_body_size: %zu < content-length: %zu", this->request_max_body_size_, content_length);
        this->buf_.clear();
        return Result<ProcResult, StatusCode>::err(ContentTooLarge);
    }

    this->request_body_.insert(this->request_body_.end(), this->buf_.begin(), this->buf_.end());
    this->buf_.clear();
    DEBUG_SERVER_PRINT("      ParseBody move buf -> request_body: size: %zu", this->request_body_.size());

    if (content_length < this->request_body_.size()) {
        DEBUG_SERVER_PRINT("      ParseBody  content_length < body.size() -> LengthRequired");
        this->request_body_.clear();
        return Result<ProcResult, StatusCode>::err(LengthRequired);
    }
    if (this->request_body_.size() < content_length) {
        DEBUG_SERVER_PRINT("      ParseBody  body.size() < content-length -> recv continue");
        return Result<ProcResult, StatusCode>::ok(Continue);
    }
    DEBUG_SERVER_PRINT("      ParseBody  body ok");
    std::string debug_body(this->request_body_.begin(), this->request_body_.end());
    DEBUG_SERVER_PRINT("       debug_body:[%s]", debug_body.c_str());
    return Result<ProcResult, StatusCode>::ok(Success);
}


Result<HostPortPair, StatusCode> HttpRequest::server_info() const {
    Result<std::map<std::string, std::string>, ProcResult> result = get_host();
    if (result.is_err()) {
        return Result<HostPortPair, StatusCode>::err(BadRequest);  // 400 Bad Request
    }
    std::map<std::string, std::string> host = result.ok_value();
    HostPortPair pair = std::make_pair(host[URI_HOST], host[PORT]);
    return Result<HostPortPair, StatusCode>::ok(pair);
}


////////////////////////////////////////////////////////////////////////////////


ProcResult HttpRequest::validate_request_headers() {
    // todo: validate field_names, such as 'must' header,...
    if (!is_valid_field_name_registered(std::string(HOST))) {
        this->set_request_status(BadRequest);
        return Failure;
    }
    return Success;
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
StatusCode HttpRequest::parse_and_validate_http_request(const std::string &input) {
	std::stringstream	ss(input);
	std::string 		line;


    // start-line CRLF
	std::getline(ss, line, LF);
    if (line.empty() || line[line.size() - 1] != CR) {
        return BadRequest;
    }
    line.erase(line.size() - 1);
    Result<ProcResult, StatusCode> request_line_result = this->request_line_.parse_and_validate(line);
	if (request_line_result.is_err()) {
		return BadRequest;
	}

	// *( field-line CRLF )
	try {
        Result<ProcResult, StatusCode> field_line_result = parse_and_validate_field_lines(&ss);

        if (field_line_result.is_err()) {
            if (field_line_result.err_value() == InternalServerError) {
                return InternalServerError;
            }
            return BadRequest;
        }
	} catch (const std::bad_alloc &e) {
		return InternalServerError;
	}

	// CRLF
	std::getline(ss, line, LF);
	if (line != std::string(1, CR)) {
		return BadRequest;
	}

	// [ message-body ]
	message_body_ = parse_message_body(&ss);
	return StatusOk;
}

////////////////////////////////////////////////////////////////////////////////
/* field-line parse and validate */

/*
 field-line CRLF
  v getline
 field-line CR

 field-line = field-name ":" OWS field-value OWS
 */
Result<ProcResult, StatusCode> HttpRequest::parse_and_validate_field_lines(std::stringstream *ss) {
	while (true) {
        std::string	line_end_with_cr;
		std::getline(*ss, line_end_with_cr, LF);
		if (ss->eof()) {
			return Result<ProcResult, StatusCode>::err(BadRequest);
		}
		if (HttpMessageParser::is_header_body_separator(line_end_with_cr)) {
			restore_crlf_to_ss(ss);
			break;
		}

        Result<std::string, StatusCode> get_line_result = get_field_line_by_remove_cr(line_end_with_cr);
		if (get_line_result.is_err()) {
			return Result<ProcResult, StatusCode>::err(BadRequest);
		}
		std::string field_line = get_line_result.ok_value();

        std::string	field_name, field_value;
        Result<ProcResult, StatusCode> field_line_result = split_field_line(
                field_line, &field_name, &field_value);
		if (field_line_result.is_err()) {
			return Result<ProcResult, StatusCode>::err(BadRequest);
		}

		if (!HttpMessageParser::is_valid_field_name_syntax(field_name)
			|| !HttpMessageParser::is_valid_field_value_syntax(field_value)) {
			return Result<ProcResult, StatusCode>::err(BadRequest);
		}

		field_name = StringHandler::to_lower(field_name);
		if (is_field_name_supported_parsing(field_name)) {
			increment_field_name_counter(field_name);

			Result<int, int>parse_result = (this->*field_value_parser_[field_name])(field_name, field_value);
			if (parse_result.is_err()) {
				return Result<ProcResult, StatusCode>::err(BadRequest);  // todo: parse error -> status
			}
			continue;
		}
	}

	// todo: validate field_names, such as 'must' header,...
	if (!is_valid_field_name_registered(std::string(HOST))) {
		// std::cout << MAGENTA << "!is valid field name registered" << RESET << std::endl;
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	return Result<ProcResult, StatusCode>::ok(Success);
}


bool is_ignore_field_name(const std::string &field_name) {
    std::vector<std::string>::const_iterator itr;

    itr = std::find(IGNORE_HEADERS.begin(), IGNORE_HEADERS.end(), field_name);
    return itr != IGNORE_HEADERS.end();
}


Result<ProcResult, StatusCode> HttpRequest::parse_and_validate_field_line(const std::string &field_line) {
    std::string	field_name, field_value;
    Result<ProcResult, StatusCode> split_result = split_field_line(field_line,
                                                                   &field_name,
                                                                   &field_value);
    if (split_result.is_err()) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }
    field_name = StringHandler::to_lower(field_name);
    if (!HttpMessageParser::is_valid_field_name_syntax(field_name)
        || !HttpMessageParser::is_valid_field_value_syntax(field_value)) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }

    if (is_ignore_field_name(field_name)) {
        return Result<ProcResult, StatusCode>::ok(Success);
    }

    std::map<std::string, func_ptr>::const_iterator func = this->field_value_parser_.find(field_name);
    if (func == this->field_value_parser_.end()) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }
    func_ptr parse_func = func->second;

    increment_field_name_counter(field_name);  // used for duplicate checking in parse_func
    Result<int, int> parse_result = (this->*parse_func)(field_name, field_value);
    if (parse_result.is_err()) {
        return Result<ProcResult, StatusCode>::err(BadRequest);  // todo: parse error -> status
    }
    return Result<ProcResult, StatusCode>::ok(Success);
}


Result<ProcResult, StatusCode> HttpRequest::parse_and_validate_field_lines(const std::string &request_headers) {
    std::stringstream ss(request_headers);
    try {
        Result<ProcResult, StatusCode> field_line_result = parse_and_validate_field_lines(&ss);
        if (field_line_result.is_err()) {
            return Result<ProcResult, StatusCode>::err(
                    field_line_result.err_value());
        }
        return Result<ProcResult, StatusCode>::ok(Success);
    } catch (const std::bad_alloc &e) {
        return Result<ProcResult, StatusCode>::err(InternalServerError);
    }
}


// field-line = field-name ":" OWS field-value OWS
Result<ProcResult, StatusCode> HttpRequest::split_field_line(const std::string &field_line,
                                                             std::string *ret_field_name,
                                                             std::string *ret_field_value) {
	if (!ret_field_name || !ret_field_value) { return Result<ProcResult, StatusCode>::err(BadRequest); }

	// field-name
	std::size_t pos = 0;
    Result<std::string, int> field_name_result = parse_field_name(field_line, &pos);
	if (field_name_result.is_err()) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	std::string field_name = field_name_result.ok_value();

	// ":"
	if (field_line[pos] != ':') {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	++pos;

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}

	// field-value
    Result<std::string, StatusCode> field_value_result = parse_field_value(field_line, &pos);
	if (field_value_result.is_err()) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
    std::string field_value = field_value_result.ok_value();

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}
	if (field_line[pos] != '\0') {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}

	*ret_field_name = field_name;
	*ret_field_value = field_value;
	return Result<ProcResult, StatusCode>::ok(Success);
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


Method HttpRequest::method() const {
    return HttpMessageParser::get_method(this->request_line_.method());
}


std::string HttpRequest::request_target() const {
	return this->request_line_.request_target();
}


std::string HttpRequest::http_version() const {
	return this->request_line_.http_version();
}


std::string HttpRequest::query_string() const {
    return this->request_line_.query();
}


const std::vector<unsigned char> HttpRequest::body() const {
    return this->request_body_;
}


bool HttpRequest::is_buf_empty() const {
    return this->buf_.empty();
}


StatusCode HttpRequest::request_status() const {
    return this->status_code_;
}


void HttpRequest::set_request_status(const StatusCode &set_code) {
    this->status_code_ = set_code;
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


RequestParsePhase HttpRequest::parse_phase() const {
    return this->phase_;
}


void HttpRequest::set_parse_phase(RequestParsePhase new_phase) {
    this->phase_ = new_phase;
}

void HttpRequest::set_max_body_size(std::size_t max_body_size) {
    this->request_max_body_size_ = max_body_size;
}


Result<std::map<std::string, std::string>, ProcResult> HttpRequest::get_host() const {
    FieldValueBase *field_values = get_field_values(HOST);
    if (!field_values) {
        return Result<std::map<std::string, std::string>, ProcResult>::err(Failure);
    }
    MapFieldValues *map_field_values = dynamic_cast<MapFieldValues *>(field_values);
    if (!map_field_values) {
        return Result<std::map<std::string, std::string>, ProcResult>::err(Failure);
    }

    std::map<std::string, std::string> host = map_field_values->get_value_map();
    return Result<std::map<std::string, std::string>, ProcResult>::ok(host);
}


Result<std::size_t, ProcResult> HttpRequest::get_content_length() const {
    FieldValueBase *field_values = get_field_values(CONTENT_LENGTH);
    if (!field_values) {
        return Result<std::size_t, ProcResult>::err(Failure);
    }
    SingleFieldValue *single_field_value = dynamic_cast<SingleFieldValue *>(field_values);
    if (!single_field_value) {
        return Result<std::size_t, ProcResult>::err(Failure);
    }

    std::string num_str = single_field_value->get_value();
    std::size_t length;
    std::istringstream iss(num_str);
    iss >> length;

    return Result<std::size_t, ProcResult>::ok(length);
}


Result<MediaType, ProcResult> HttpRequest::get_content_type() const {
    FieldValueBase *field_values = get_field_values(CONTENT_TYPE);
    if (!field_values) {
        return Result<MediaType, ProcResult>::err(Failure);
    }
    MediaType *media_type = dynamic_cast<MediaType *>(field_values);
    if (!media_type) {
        return Result<MediaType, ProcResult>::err(Failure);
    }
    return Result<MediaType, ProcResult>::ok(*media_type);
}


std::string HttpRequest::content_type() const {
    Result<MediaType, ProcResult> result = get_content_type();
    if (result.is_err()) {
        return EMPTY;
    }
    MediaType media_type = result.ok_value();
    std::string content_type = media_type.type();
    if (!media_type.subtype().empty()) {
        content_type.append("/");
        content_type.append(media_type.subtype());
    }
    return content_type;
}


const std::vector<unsigned char> &HttpRequest::get_buf() const {
    return this->buf_;
}
