#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

/*
 cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                ; US-ASCII characters excluding CTLs,
                ; whitespace DQUOTE, comma, semicolon,
                ; and backslash
 */
bool is_cookie_octet(char c) {
    if (c == ',' || c == ' ') {  // update for `expires`
        return true;
    }

	return (c == 0x21
			|| (0x23 <= c && c <= 0x2B)
			|| (0x2D <= c && c <= 0x3A)
			|| (0x3C <= c && c <= 0x5B)
			|| (0x5D <= c && c <= 0x7E));
}

// cookie-name = token
void skip_cookie_name(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	HttpMessageParser::skip_token(str, start_pos, end_pos);
}

// cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
void skip_cookie_value(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	std::size_t len;
	bool is_quoted;

	if (!end_pos) { return; }

	len = 0;
	if (str[start_pos] == DOUBLE_QUOTE) {
		is_quoted = true;
		++len;
	} else {
		is_quoted = false;
	}

	while (str[start_pos + len] && is_cookie_octet(str[start_pos + len])) {
		++len;
	}

	if (is_quoted) {
		if (str[start_pos + len] == DOUBLE_QUOTE) {
			++len;
		} else {
			return;
		}
	}
	if (len == 0) { return; }
	*end_pos = start_pos + len;
}

Result<std::size_t, int> skip_to_next_cookie_pair(const std::string &field_value,
												  std::size_t start_pos) {
	std::size_t pos;
	const std::size_t comma_and_sp_len = 2;

	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::size_t, int>::err(ERR);
	}

	pos = start_pos;
	if (field_value[pos] == SEMICOLON && field_value[pos + 1] == SP) {
		pos += comma_and_sp_len;
	}
	return Result<std::size_t, int>::ok(pos);
}


const std::size_t MAX_COOKIES = 50;
const std::size_t MAX_SIZE = 4096;

bool is_over_limits(const std::map<std::string, std::string> &cookie_strings) {
    if (MAX_COOKIES < cookie_strings.size()) {
        return true;
    }
    std::size_t size = 0;
    std::map<std::string, std::string>::const_iterator itr;
    for (itr = cookie_strings.begin(); itr != cookie_strings.end(); ++itr) {
        size += itr->first.length() + itr->second.length();
        if (MAX_SIZE < size) {
            return true;
        }
    }
    return false;
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

/*
 cookie-header = "Cookie:" OWS cookie-string OWS
 cookie-string = cookie-pair *( ";" SP cookie-pair )

 cookie-pair       = cookie-name "=" cookie-value
 cookie-name       = token
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                       ; US-ASCII characters excluding CTLs,
                       ; whitespace DQUOTE, comma, semicolon,
                       ; and backslash
 https://tex2e.github.io/rfc-translater/html/rfc6265.html#4-2-1--Syntax
 */
Result<int, int> HttpRequest::set_cookie(const std::string &field_name,
										 const std::string &field_value) {
	std::map<std::string, std::string> cookie_string;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);
	result = HttpMessageParser::parse_map_field_values(field_value,
													   skip_cookie_name,
													   skip_cookie_value,
													   skip_to_next_cookie_pair);
	if (result.is_ok()) {
		cookie_string = result.ok_value();
        if (!is_over_limits(cookie_string)) {
		    this->request_header_fields_[field_name] = new MapFieldValues(cookie_string);
        }
	}
	return Result<int, int>::ok(STATUS_OK);
}
