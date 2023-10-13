#include <algorithm>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &all_value)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(all_value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, '/');
	std::getline(ss, second_value, '/');

	return (new TwoValueSet(first_value, second_value));
}

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &value, char delimiter)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, delimiter);
	std::getline(ss, second_value, delimiter);
	return (new TwoValueSet(HttpMessageParser::obtain_withoutows_value(first_value), HttpMessageParser::obtain_withoutows_value(second_value)));
}

// authorizationはちょっと格納方法変えるかもしれない
// todo: Authorization
// Authorization: <type> <credentials>
// Authorization = credentials
// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
// auth-scheme   = token
// auth-param    = token BWS "=" BWS ( token / quoted-string )
// token68       = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
// https://datatracker.ietf.org/doc/html/rfc7235#section-4.2

// todo:
//  map[type]
//  map[credentials]
//  get(key) -> "" or value
Result<int, int> HttpRequest::set_authorization(const std::string &key, const std::string &value)
{
	// Digest username=<username>,realm="<realm>",uri="<url>",algorithm=<algorithm>,nonce="<nonce>",
	// ValueMapに変更
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ' ');
	return Result<int, int>::ok(STATUS_OK);
}

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
// todo:
//  map[uri_host]
//  map[port]
// 0 <= port <= 65535
Result<int, int> HttpRequest::set_host(const std::string &key, const std::string &value)
{
	// std::string	first_value;
	// std::string	second_value;

	if (std::count(value.begin(), value.end(), ':') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ':'));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ':'));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
	}
	else if (std::count(value.begin(), value.end(), ':') > 1)
	{
		this->_status_code = 400;
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ':');
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Proxy-Authorization
Result<int, int> HttpRequest::set_proxy_authorization(const std::string &key, const std::string &value)
{
	if (std::count(value.begin(), value.end(), ' ') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ' '));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ' '));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
	}
	else if (std::count(value.begin(), value.end(), ' ') > 1)
	{
		this->_status_code = 400;
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ' ');
	return Result<int, int>::ok(STATUS_OK);
}
