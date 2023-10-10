#include <algorithm>
#include <sstream>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "Color.hpp"

/* sub funcs; unnamed namespace */
namespace {

// field-line = field-name ":" OWS field-value OWS
//              ^head       ^colon
Result<std::string, int> parse_field_name(const std::string &field_line,
										  std::size_t *pos) {
	std::size_t head_pos, colon_pos, len;
	std::string field_name;

	if (!pos) { return Result<std::string, int>::err(NG); }

	head_pos = 0;
	colon_pos = field_line.find(':', head_pos);
	if (colon_pos == std::string::npos || colon_pos <= head_pos) {
		return Result<std::string, int>::err(NG);
	}
	len = colon_pos - head_pos;

	field_name = field_line.substr(head_pos, len);
	*pos += len;
	return Result<std::string, int>::ok(field_name);
}

// field-line CRLF
// field-line = field-name ":" OWS field-value OWS
//                                 ^head
Result<std::string, int> parse_field_value(const std::string &field_line,
										   std::size_t *head_pos) {
	std::size_t len, ws_len;
	std::string field_value;

	if (!head_pos) { return Result<std::string, int>::err(NG); }

	len = 0;
	while (field_line[*head_pos + len]) {
		while (field_line[*head_pos + len]
			   && !HttpMessageParser::is_whitespace(field_line[*head_pos + len])) {
			++len;
		}
		ws_len = 0;
		while (HttpMessageParser::is_whitespace(field_line[*head_pos + len + ws_len])) {
			++ws_len;
		}
		if (field_line[*head_pos + len + ws_len] == '\0') {
			break;
		}
		len += ws_len;
	}

	field_value = field_line.substr(*head_pos, len);
	*head_pos += len;
	return Result<std::string, int>::ok(field_value);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
/* constructor, destructor */

HttpRequest::HttpRequest(const std::string &input) {
	init_field_name_parser();
	this->_status_code = parse_and_validate_http_request(input);
}

HttpRequest::~HttpRequest()
{
	std::map<std::string, FieldValues*>::iterator itr;

	itr = this->_request_header_fields.begin();
	while (itr != this->_request_header_fields.end()) {
		delete itr->second;
		++itr;
	}
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
	Result<int, int>	request_line_result;
	Result<int, int>	field_line_result;

	// start-line CRLF
	std::getline(ss, line, LF);
	request_line_result = this->_request_line.parse_and_validate(line);
	if (request_line_result.is_err()) {
		return STATUS_BAD_REQUEST;
	}

	// *( field-line CRLF )
	try {
		field_line_result = parse_and_validate_field_lines(&ss);
	} catch (const std::bad_alloc &e) {
		return STATUS_SERVER_ERROR;
	}
	if (field_line_result.is_err()) {
		return STATUS_BAD_REQUEST;
	}

	// CRLF
	std::getline(ss, line, LF);
	if (line != std::string(1, CR)) {
		return STATUS_BAD_REQUEST;
	}

	// [ message-body ]
	_message_body = parse_message_body(&ss);
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
Result<int, int> HttpRequest::parse_and_validate_field_lines(std::stringstream *ss) {
	std::string			line_end_with_cr, field_line, field_name, field_value;
	Result<int, int> 	parse_result;

	while (true) {
		std::getline(*ss, line_end_with_cr, LF);
		if (ss->eof()) {
			return Result<int, int>::err(NG);
		}
		if (line_end_with_cr == std::string(CRLF)) {
			std::streampos current_pos = ss->tellg();
			ss->seekg(current_pos - std::streamoff(std::string(CRLF).length()));
			break;
		}

		if (!HttpMessageParser::is_end_with_cr(line_end_with_cr)) {
			return Result<int, int>::err(NG);
		}
		field_line = line_end_with_cr.substr(0, line_end_with_cr.length() - 1);

		parse_result = parse_field_line(field_line, &field_name, &field_value);
		if (parse_result.is_err()) {
			return Result<int, int>::err(NG);
		}

		if (!is_valid_field_name_syntax(field_name)
			|| !is_valid_field_value_syntax(field_value)) {
			return Result<int, int>::err(NG);
		}

		if (is_valid_field_name(field_name)) {
			(this->*_field_value_parser[field_name])(field_name, field_value);
		}
	}

	// todo: validate field_names, such as 'must' header,...
	return Result<int, int>::ok(OK);
}


// field-line = field-name ":" OWS field-value OWS
Result<int, int> HttpRequest::parse_field_line(const std::string &field_line,
								  std::string *ret_field_name,
								  std::string *ret_field_value) {
	Result<std::string, int> field_name_result, field_value_result;
	std::string			field_name, field_value;
	std::size_t			pos;

	if (!ret_field_name || !ret_field_value) { return Result<int, int>::err(NG); }

	// field-name
	pos = 0;
	field_name_result = parse_field_name(field_line, &pos);
	if (field_name_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	field_name = field_name_result.get_ok_value();

	// ":"
	if (field_line[pos] != ':') {
		return Result<int, int>::err(NG);
	}
	++pos;

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}

	// field-value
	field_value_result = parse_field_value(field_line, &pos);
	if (field_value_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	field_value = field_value_result.get_ok_value();

	// OWS
	while (HttpMessageParser::is_whitespace(field_line[pos])) {
		++pos;
	}
	if (field_line[pos] != '\0') {
		return Result<int, int>::err(NG);
	}

	*ret_field_name = field_name;
	*ret_field_value = field_value;
	return Result<int, int>::ok(OK);
}

// field-name = token
bool HttpRequest::is_valid_field_name_syntax(const std::string &field_name) {
	return HttpMessageParser::is_token(field_name);
}

// field-value = *( field-content )  // todo: empty??
bool HttpRequest::is_valid_field_value_syntax(const std::string &field_value) {
	if (field_value.empty()) {
		return false;
	}
	if (!HttpMessageParser::is_field_content(field_value)) {
		return false;
	}
	return true;
}

// [ message-body ]
std::string HttpRequest::parse_message_body(std::stringstream *ss) {
	return ss->str();
}

bool HttpRequest::is_valid_field_name(const std::string &field_name) {
	 return (this->_field_value_parser.count(field_name) > 0);
}

////////////////////////////////////////////////////////////////////////////////


// weightarrayset わかりやすいように
bool HttpRequest::is_weightformat(const std::string &value)
{
	size_t		semicolon_pos = value.find(';');
	std::string	field_value_weight = value.substr(semicolon_pos + 1);
	std::string	weight_key;
	std::string	weight_num;

	if (std::count(field_value_weight.begin(), field_value_weight.end(), '=') != 1)
		return (false);
	weight_key = field_value_weight.substr(0, field_value_weight.find('='));
	if (weight_key != "q")
		return (false);
	weight_num = field_value_weight.substr(field_value_weight.find('=') + 1);
	return StringHandler::is_positive_under_intmax_double(weight_num);
}

// まだできてない
void HttpRequest::set_cache_control(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// Digest username=<username>,realm="<realm>",uri="<url>",algorithm=<algorithm>,nonce="<nonce>",
	// ValueMapに変更
	// this->_request_header_fields[key] = ready_ValueWeightArraySet(value);
}

void HttpRequest::set_content_security_policy_report_only(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// std::cout << key << " and " << "value is " << value << std::endl;
	// this->_request_header_fields[key] = ready_SecurityPolicy();
}

void HttpRequest::set_servertiming(const std::string &key, const std::string &value)
{
	// cpu;dur=2.4;a=b, cpu; ,,,みたいな感じなのでmapで保持しないほうがいいかもしれない
	// this->_request_header_fields[key] = ready_ValueMap(value);
	(void)key;
	(void)value;
}

void HttpRequest::set_x_xss_protection(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
}

void HttpRequest::init_field_name_parser()
{
	this->_field_value_parser["Accept"] = &HttpRequest::set_accept;
	this->_field_value_parser["Accept-CH"] = &HttpRequest::set_accept_ch;
	this->_field_value_parser["Accept-Charset"] = &HttpRequest::set_accept_charset;
	this->_field_value_parser["Accept-Encoding"] = &HttpRequest::set_accept_encoding;
	this->_field_value_parser["Accept-Language"] = &HttpRequest::set_accept_language;
	// this->_field_value_parser["Accept-Patch"] = this->set_accept_patch;
	this->_field_value_parser["Accept-Post"] = &HttpRequest::set_accept_post;
	this->_field_value_parser["Accept-Ranges"] = &HttpRequest::set_accept_ranges;
	this->_field_value_parser["Access-Control-Allow-Credentials"] = &HttpRequest::set_access_control_allow_credentials;
	this->_field_value_parser["Access-Control-Allow-Headers"] = &HttpRequest::set_access_control_allow_headers;
	this->_field_value_parser["Access-Control-Allow-Methods"] = &HttpRequest::set_access_control_allow_methods;
	this->_field_value_parser["Access-Control-Allow-Origin"] = &HttpRequest::set_access_control_allow_origin;
	this->_field_value_parser["Access-Control-Expose-Headers"] = &HttpRequest::set_access_control_expose_headers;
	this->_field_value_parser["Access-Control-Max-Age"] = &HttpRequest::set_access_control_max_age;
	this->_field_value_parser["Access-Control-Request-Headers"] = &HttpRequest::set_access_control_request_headers;
	this->_field_value_parser["Access-Control-Request-Method"] = &HttpRequest::set_access_control_request_method;
	this->_field_value_parser["Age"] = &HttpRequest::set_age;
	this->_field_value_parser["Allow"] = &HttpRequest::set_allow;
	this->_field_value_parser["Alt-Svc"] = &HttpRequest::set_alt_svc;
	this->_field_value_parser["Alt-Used"] = &HttpRequest::set_alt_used;
	this->_field_value_parser["Authorization"] = &HttpRequest::set_authorization;
	this->_field_value_parser["Cache-Control"] =  &HttpRequest::set_cache_control;
	this->_field_value_parser["Clear-Site-Data"] = &HttpRequest::set_clear_site_data;
	this->_field_value_parser["Connection"] = &HttpRequest::set_connection;
	this->_field_value_parser["Content-Disposition"] = &HttpRequest::set_content_disponesition;
	this->_field_value_parser["Content-Encoding"] = &HttpRequest::set_content_encoding;
	this->_field_value_parser["Content-Language"] = &HttpRequest::set_content_language;
	this->_field_value_parser["Content-Length"] = &HttpRequest::set_content_length;
	this->_field_value_parser["Content-Location"] = &HttpRequest::set_content_location;
	this->_field_value_parser["Content-Range"] = &HttpRequest::set_content_range;
	this->_field_value_parser["Content-Security-Policy"] = &HttpRequest::set_content_security_policy;
	this->_field_value_parser["Content-Security-Policy-Report-Only"] = &HttpRequest::set_content_security_policy_report_only;
	this->_field_value_parser["Content-Type"] = &HttpRequest::set_content_type;
	this->_field_value_parser["Cookie"] = &HttpRequest::set_cookie;
	this->_field_value_parser["Cross-Origin-Embedder-Policy"] = &HttpRequest::set_cross_origin_embedder_policy;
	this->_field_value_parser["Cross-Origin-Opener-Policy"] = &HttpRequest::set_cross_origin_opener_policy;
	this->_field_value_parser["Cross-Origin-Resource-Policy"] = &HttpRequest::set_cross_origin_resource_policy;
	this->_field_value_parser["Date"] = &HttpRequest::set_date;
	this->_field_value_parser["ETag"] = &HttpRequest::set_etag;
	this->_field_value_parser["Expect"] = &HttpRequest::set_expect;
	// this->_field_value_parser["Expect-CT"] = this->set_expect_ct;
	this->_field_value_parser["Expires"] = &HttpRequest::set_expires;
	this->_field_value_parser["Forwarded"] = &HttpRequest::set_forwarded;
	this->_field_value_parser["From"] = &HttpRequest::set_from;
	this->_field_value_parser["Host"] = &HttpRequest::set_host;
	this->_field_value_parser["If-Match"] = &HttpRequest::set_if_match;
	this->_field_value_parser["If-Modified-Since"] = &HttpRequest::set_if_modified_since;
	this->_field_value_parser["If-None-Match"] = &HttpRequest::set_if_none_match;
	this->_field_value_parser["If-Range"] = &HttpRequest::set_if_range;
	this->_field_value_parser["If-Unmodified-Since"] = &HttpRequest::set_if_unmodified_since;
	this->_field_value_parser["Keep-Alive"] = &HttpRequest::set_keep_alive;
	this->_field_value_parser["Last-Modified"] = &HttpRequest::set_last_modified;
	this->_field_value_parser["Link"] = &HttpRequest::set_link;
	this->_field_value_parser["Location"] = &HttpRequest::set_location;
	this->_field_value_parser["Max-Forwards"] = &HttpRequest::set_max_forwards;
	this->_field_value_parser["Origin"] = &HttpRequest::set_origin;
	this->_field_value_parser["Permission-Policy"] = &HttpRequest::set_permission_policy;
	this->_field_value_parser["Proxy-Authenticate"] = &HttpRequest::set_proxy_authenticate;
	this->_field_value_parser["Proxy-Authorization"] = &HttpRequest::set_proxy_authorization;
	// this->_field_value_parser["Range"] = this->set_range;
	this->_field_value_parser["Referer"] = &HttpRequest::set_referer;
	this->_field_value_parser["Retry-After"] = &HttpRequest::set_retry_after;
	this->_field_value_parser["Sec-Fetch-Dest"] = &HttpRequest::set_sec_fetch_dest;
	this->_field_value_parser["Sec-Fetch-Mode"] = &HttpRequest::set_sec_fetch_mode;
	this->_field_value_parser["Sec-Fetch-Site"] = &HttpRequest::set_sec_fetch_site;
	this->_field_value_parser["Sec-Fetch-User"] = &HttpRequest::set_sec_fetch_user;
	this->_field_value_parser["Sec-Purpose"] = &HttpRequest::set_sec_purpose;
	this->_field_value_parser["Sec-WebSocket-Accept"] = &HttpRequest::set_sec_websocket_accept;
	this->_field_value_parser["Server"] = &HttpRequest::set_server;
	// this->_field_value_parser["Server-Timing"] = this->set_server_timing;
	this->_field_value_parser["Service-Worker-Navigation-Preload"] = &HttpRequest::set_service_worker_navigation_preload;
	this->_field_value_parser["Set-Cookie"] = &HttpRequest::set_cookie;
	this->_field_value_parser["SourceMap"] = &HttpRequest::set_sourcemap;
	this->_field_value_parser["Strict-Transport-Security"] = &HttpRequest::set_strict_transport_security;
	this->_field_value_parser["TE"] = &HttpRequest::set_te;
	this->_field_value_parser["Timing-Allow-Origin"] = &HttpRequest::set_timing_allow_origin;
	this->_field_value_parser["Trailer"] = &HttpRequest::set_trailer;
	this->_field_value_parser["Transfer-Encoding"] = &HttpRequest::set_transfer_encoding;
	this->_field_value_parser["Upgrade"] = &HttpRequest::set_upgrade;
	this->_field_value_parser["Upgrade-Insecure-Requests"] = &HttpRequest::set_upgrade_insecure_requests;
	this->_field_value_parser["User-Agent"] = &HttpRequest::set_user_agent;
	this->_field_value_parser["Vary"] = &HttpRequest::set_vary;
	this->_field_value_parser["Via"] = &HttpRequest::set_via;
	this->_field_value_parser["WWW-Authenticate"] = &HttpRequest::set_www_authenticate;
	// this->_field_value_parser["X-Custom-Header"] = &HttpRequest::set_x_custom_header;
}

std::string HttpRequest::get_method() const {
	return this->_request_line.get_method();
}

std::string HttpRequest::get_request_target() const {
	return this->_request_line.get_request_target();
}

std::string HttpRequest::get_http_version() const {
	return this->_request_line.get_http_version();
}

FieldValues* HttpRequest::get_field_values(const std::string &key) {
	return this->_request_header_fields[key];
}

std::map<std::string, FieldValues*> HttpRequest::get_request_header_fields(void) {
	return this->_request_header_fields;
}

int	HttpRequest::get_status_code() const {
	return this->_status_code;
}
