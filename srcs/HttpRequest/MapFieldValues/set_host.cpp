#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"
#include "Result.hpp"

namespace {

/*
 uri-host    = IP-literal / IPv4address / reg-name

 IP-literal  = "[" ( IPv6address / IPvFuture  ) "]"

 IPv6address =                            6( h16 ":" ) ls32
             /                       "::" 5( h16 ":" ) ls32
             / [               h16 ] "::" 4( h16 ":" ) ls32
             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
             / [ *4( h16 ":" ) h16 ] "::"              ls32
             / [ *5( h16 ":" ) h16 ] "::"              h16
             / [ *6( h16 ":" ) h16 ] "::"
 h16         = 1*4HEXDIG
             ; 16 bits of address represented in hexadecimal
 ls32        = ( h16 ":" h16 ) / IPv4address
             ; least-significant 32 bits of address

 IPvFuture   = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

 IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
 dec-octet   = DIGIT                 ; 0-9
             / %x31-39 DIGIT         ; 10-99
             / "1" 2DIGIT            ; 100-199
             / "2" %x30-34 DIGIT     ; 200-249
             / "25" %x30-35          ; 250-255

 reg-name    = *( unreserved / pct-encoded / sub-delims )
 unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
 pct-encoded = "%" HEXDIG HEXDIG
 sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
 */
Result <std::string, int> parse_uri_host(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos) {
	std::size_t pos, end, len;
	std::string uri_host;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	if (field_value[pos] == '[') {
		HttpMessageParser::skip_ip_literal(field_value, pos, &end);
	} else if (std::isdigit(field_value[pos])) {
		HttpMessageParser::skip_ipv4address(field_value, pos, &end);
	} else if (HttpMessageParser::is_unreserved(field_value[pos])
			|| field_value[pos] == '%'
			|| HttpMessageParser::is_sub_delims(field_value[pos])) {
		HttpMessageParser::skip_reg_name(field_value, pos, &end);
	} else {
		return Result<std::string, int>::err(ERR);
	}

	if (pos == end) {
		return Result<std::string, int>::err(ERR);
	}
	len = end - pos;
	uri_host = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<std::string, int>::ok(uri_host);
}

/*
 port          = *DIGIT
 */
Result <std::string, int> parse_port(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos) {
	std::size_t pos, len;
	std::string port;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	pos = start_pos;
	len = 0;
	while (field_value[pos + len] && std::isdigit(field_value[pos + len])) {
		++len;
	}
	if (len == 0) {
		return Result<std::string, int>::err(ERR);
	}
	port = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<std::string, int>::ok(port);
}

Result<std::map<std::string, std::string>, int> parse_host(const std::string &field_value) {
	std::map<std::string, std::string> host;
	std::size_t pos, end;
	std::string uri_host, port;
	Result<std::string, int> uri_host_result, port_result;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	uri_host_result = parse_uri_host(field_value, pos, &end);
	if (uri_host_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	uri_host = uri_host_result.get_ok_value();
	host[std::string(URI_HOST)] = uri_host;
	pos = end;

	if (field_value[pos] != '\0') {
		if (field_value[pos] != ':') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;

		port_result = parse_port(field_value, pos, &end);
		if (port_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		port = port_result.get_ok_value();
		host[std::string(PORT)] = port;
		pos = end;

		if (field_value[pos] != '\0') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
	}
	return Result<std::map<std::string, std::string>, int>::ok(host);
}

Result<int, int> validate_uri_host(const std::map<std::string, std::string> &host) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string uri_host;

	itr = host.find(std::string(URI_HOST));
	if (itr == host.end()) {
		return Result<int, int>::err(ERR);
	}
	uri_host = itr->second;

	if (!HttpMessageParser::is_ip_literal(uri_host)
		&& !HttpMessageParser::is_ipv4address(uri_host)
		&& !HttpMessageParser::is_reg_name(uri_host)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<int, int> validate_port(const std::map<std::string, std::string> &host) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string port;
	int port_num;
	bool succeed;

	itr = host.find(std::string(PORT));
	if (itr == host.end()){
		return Result<int, int>::ok(OK);
	}

	port = itr->second;
	port_num = HttpMessageParser::to_integer_num(port, &succeed);
	if (!succeed || port_num < 0 || 65535 < port_num) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<int, int> validate_host(const std::map<std::string, std::string> &host) {
	Result<int, int> uri_host_result, port_result;

	if (host.empty()) {
		return Result<int, int>::err(ERR);
	}

	uri_host_result = validate_uri_host(host);
	if (uri_host_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	port_result = validate_port(host);
	if (port_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<std::map<std::string, std::string>, int>
parse_and_validate_host(const std::string &field_value) {
	std::map<std::string, std::string> host;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	parse_result = parse_host(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	host = parse_result.get_ok_value();

	validate_result = validate_host(host);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(host);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

// todo: Host
// Host: <host>:<port>

/*
 Host = uri-host [ ":" port ]
 uri-host = IP-literal / IPv4address / reg-name
 IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
 IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

      IPv6address =                            6( h16 ":" ) ls32
                  /                       "::" 5( h16 ":" ) ls32
                  / [               h16 ] "::" 4( h16 ":" ) ls32
                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                  / [ *4( h16 ":" ) h16 ] "::"              ls32
                  / [ *5( h16 ":" ) h16 ] "::"              h16
                  / [ *6( h16 ":" ) h16 ] "::"

      ls32        = ( h16 ":" h16 ) / IPv4address
                  ; least-significant 32 bits of address

      h16         = 1*4HEXDIG
                  ; 16 bits of address represented in hexadecimal

      IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet

      dec-octet   = DIGIT                 ; 0-9
                  / %x31-39 DIGIT         ; 10-99
                  / "1" 2DIGIT            ; 100-199
                  / "2" %x30-34 DIGIT     ; 200-249
                  / "25" %x30-35          ; 250-255

 reg-name    = *( unreserved / pct-encoded / sub-delims )
 unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
 pct-encoded   = "%" HEXDIG HEXDIG
 sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="

 port          = *DIGIT

https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
 */
// 0 <= port <= 65535

// map["uri-host"] = uri-host
// map["port"] = port
Result<int, int> HttpRequest::set_host(const std::string &field_name,
									   const std::string &field_value) {
	std::map<std::string, std::string> host;
	Result<std::map<std::string, std::string>, int> result;

	if (is_field_name_repeated_in_request(field_name)) {
		clear_field_values_of(field_name);
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	result = parse_and_validate_host(field_value);
	if (result.is_err()) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	host = result.get_ok_value();

	this->_request_header_fields[field_name] = new MapFieldValues(host);
	return Result<int, int>::ok(STATUS_OK);
}

