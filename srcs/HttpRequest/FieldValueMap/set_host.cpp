#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueMap.hpp"

namespace {


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
Result<int, int> HttpRequest::set_host(const std::string &field_name,
									   const std::string &field_value)
{
	// std::string	first_value;
	// std::string	second_value;

	if (std::count(field_value.begin(), field_value.end(), ':') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(field_value, ':'));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(field_value, ':'));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
	}
	else if (std::count(field_value.begin(), field_value.end(), ':') > 1)
	{
		this->_status_code = 400;
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	this->_request_header_fields[field_name] = this->ready_TwoValueSet(field_value, ':');
	return Result<int, int>::ok(STATUS_OK);
}

