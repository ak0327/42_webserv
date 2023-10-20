#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"
#include "Result.hpp"

namespace {

Result<std::map<std::string, std::string>, int> parse_host(const std::string &field_value) {
	std::map<std::string, std::string> host;
	std::size_t pos, end;
	std::string uri_host, port;
	Result<std::string, int> uri_host_result, port_result;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	uri_host_result = HttpMessageParser::parse_uri_host(field_value, pos, &end);
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

		port_result = HttpMessageParser::parse_port(field_value, pos, &end);
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

	if (!HttpMessageParser::is_uri_host(uri_host)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<int, int> validate_port(const std::map<std::string, std::string> &host) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string port;


	itr = host.find(std::string(PORT));
	if (itr == host.end()){
		return Result<int, int>::ok(OK);
	}

	port = itr->second;
	if (!HttpMessageParser::is_port(port)) {
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

// Alt-Used = uri-host [ ":" port ]
// https://tex2e.github.io/rfc-translater/html/rfc7838.html#5--The-Alt-Used-HTTP-Header-Field
Result<int, int> HttpRequest::set_alt_used(const std::string &field_name,
										   const std::string &field_value) {
	std::map<std::string, std::string> host;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_host(field_value);
	if (result.is_err()) {
		return Result<int, int>::ok(STATUS_OK);
	}
	host = result.get_ok_value();

	this->_request_header_fields[field_name] = new MapFieldValues(host);
	return Result<int, int>::ok(STATUS_OK);
}
