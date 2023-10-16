#include <ctype.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"

namespace {

double get_integer_part(const std::string &str, size_t idx) {
	if (str.length() < idx) {
		return ERR;
	}
	return StringHandler::to_digit(str[idx]);
}

double get_fractional_part(const std::string &str_after_decimal_point,
						   size_t *precision_idx) {
	double	digit, num;
	int		precision_num;
	size_t	idx;

	num = 0;
	digit = 1;
	idx = 0;
	while (isdigit(str_after_decimal_point[idx])) {
		precision_num = StringHandler::to_digit(str_after_decimal_point[idx]);
		num = num * 10 + precision_num;
		digit *= 10;
		++idx;
	}
	*precision_idx = idx;
	num /= digit;
	return num;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

namespace HttpMessageParser {

bool is_printable(const std::string &str)
{
	std::size_t pos;

	pos = 0;
	while (str[pos])
	{
		if (!isprint(str[pos])) {
			return false;
		}
		++pos;
	}
	return true;
}

std::string obtain_word_before_delimiter(const std::string &field_value, const char &delimiter)
{
	return field_value.substr(0, field_value.find(delimiter));
}

std::string obtain_word_after_delimiter(const std::string &str, char delimiter)
{
	return str.substr(str.find(delimiter) + 1);
}

std::string	obtain_weight(const std::string &field_value)
{
	return (obtain_word_after_delimiter(field_value, '='));
}

std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (is_whitespace(field_value_with_ows[before_pos]) == true && before_pos != field_value_with_ows.length())
		++before_pos;
	while (is_whitespace(field_value_with_ows[after_pos]) == true && after_pos != 0)
		--after_pos;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}


// DIGIT = %x30-39; 10 進数字（ 0-9 ）
// sign, space is not allowed for Request message
int to_integer_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	int			num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stoi(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

// delta-seconds = 1*DIGIT
// The delta-seconds rule specifies a non-negative integer
int to_delta_seconds(const std::string &str, bool *succeed) {
	return to_integer_num(str, succeed);
}

long to_long_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	long		num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stol(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

long to_length(const std::string &str, bool *succeed) {
	return to_long_num(str, succeed);
}

// HTTP-version	= HTTP-name "/" DIGIT "." DIGIT
// qvalue = ( "0" [ "." 0*3DIGIT ] )
//        / ( "1" [ "." 0*3("0") ] )
//
//  1.234
//    ^^^ precision_digit = 3
double to_floating_num(const std::string &str,
										  size_t precision_digit,
										  bool *succeed) {
	bool		is_success;
	double 		num, precision_num;
	std::size_t	idx, precision_idx;

	is_success = false;
	if (succeed) { *succeed = is_success; }
	num = 0;
	idx = 0;
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = get_integer_part(str, idx);
	++idx;

	if (str[idx] != DECIMAL_POINT) {
		if (str[idx] == '\0') {
			is_success = true;
		}
		if (succeed) { *succeed = is_success; }
		return num;
	}
	++idx;

	precision_num = get_fractional_part(&str[idx], &precision_idx);
	num += precision_num;

	if (str[idx + precision_idx] == '\0' && precision_idx <= precision_digit) {
		is_success = true;
	}
	if (succeed) { *succeed = is_success; }
	return num;
}

// Delimiters : set of US-ASCII visual characters not allowed in a token
//  (DQUOTE and "(),/:;<=>?@[\]{}").
bool is_delimiters(char c) {
	return std::string(DELIMITERS).find(c) != std::string::npos;
}

// VCHAR = %x21-7E ; (any visible [USASCII] character).
bool is_vchar(char c) {
	return std::isprint(c);
}

// obs-text = %x80-FF
bool is_obs_text(char c) {
	int uc = static_cast<unsigned char>(c);

	return (0x80 <= uc && uc <= 0xFF);
}

// field-vchar = VCHAR / obs-text
bool is_field_vchar(char c) {
	return (is_vchar(c) || is_obs_text(c));
}

// field-content = field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]
bool is_field_content(const std::string &str) {
	std::size_t pos;

	pos = 0;
	if (!HttpMessageParser::is_vchar(str[pos])) {
		return false;
	}
	while (str[pos]) {
		while (HttpMessageParser::is_whitespace(str[pos])) {
			++pos;
		}
		if (!HttpMessageParser::is_field_vchar(str[pos])) {
			return false;
		}
		while (HttpMessageParser::is_field_vchar(str[pos])) {
			++pos;
		}
	}
	return true;
}

// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//      / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//      / DIGIT / ALPHA
//      ; any VCHAR, except delimiters
bool is_tchar(char c) {
	return (std::isalnum(c)
			|| c == '!' || c == '#' || c == '$' || c == '%'
			|| c == '&' || c == '\'' || c == '*' || c == '+'
			|| c == '-' || c == '.' || c == '^' || c == '_'
			|| c == '`' || c == '|' || c == '|' || c == '~');

	// if (!is_vchar(c)) {
	// 	return false;
	// }
	// if (is_delimiters(c) || is_whitespace(c)) {
	// 	return false;
	// }
	// return true;
}

// token = 1*tchar
bool is_token(const std::string &str) {
	std::size_t pos;

	if (str.empty()) {
		return false;
	}

	pos = 0;
	while (str[pos]) {
		if (!is_tchar(str[pos])) {
			return false;
		}
		++pos;
	}
	return true;
}

// token68       = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
bool is_token68(const std::string &str) {
	std::size_t pos;

	if (str.empty()) { return false; }

	pos = 0;
	while (std::isalnum(str[pos])
		   || str[pos] == '-' || str[pos] == '.' || str[pos] == '_'
		   || str[pos] == '~'|| str[pos] == '+' || str[pos] == '/') {
		++pos;
	}
	if (pos == 0) { return false; }

	while (str[pos] == '=') {
		++pos;
	}

	return str[pos] == '\0';
}

/*
 ext-token  = <the characters in token, followed by "*">
 https://httpwg.org/specs/rfc6266.html#n-grammar
 */
bool is_ext_token(const std::string &key) {
	std::size_t pos;

	if (key.empty()) { return false; }
	pos = 0;
	while (key[pos] && HttpMessageParser::is_tchar(key[pos])) {
		++pos;
	}
	if (pos == 0 || key[pos] != '*') { return false; }
	++pos;
	return key[pos] == '\0';
}

/*
 Language-Tag  = langtag             ; normal language tags
               / privateuse          ; private use tag
               / grandfathered       ; grandfathered tags

 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]

 language      = 2*3ALPHA            ; shortest ISO 639 code
                 ["-" extlang]       ; sometimes followed by
                                     ; extended language subtags
               / 4ALPHA              ; or reserved for future use
               / 5*8ALPHA            ; or registered language subtag

 extlang       = 3ALPHA              ; selected ISO 639 codes
                 *2("-" 3ALPHA)      ; permanently reserved


 script = 4ALPHA ; ISO 15924 code

 region        = 2ALPHA              ; ISO 3166-1 code
               / 3DIGIT              ; UN M.49 code

 variant       = 5*8alphanum         ; registered variants
               / (DIGIT 3alphanum)
 alphanum      = (ALPHA / DIGIT)     ; letters and numbers

 extension     = singleton 1*("-" (2*8alphanum))

 singleton     = DIGIT               ; 0 - 9
               / %x41-57             ; A - W
               / %x59-5A             ; Y - Z
               / %x61-77             ; a - w
               / %x79-7A             ; y - z

 privateuse    = "x" 1*("-" (1*8alphanum))

 grandfathered = irregular           ; non-redundant tags registered
               / regular             ; during the RFC 3066 era

 irregular     = "en-GB-oed"         ; irregular tags do not match
               / "i-ami"             ; the 'langtag' production and
               / "i-bnn"             ; would not otherwise be
               / "i-default"         ; considered 'well-formed'
               / "i-enochian"        ; These tags are all valid,
               / "i-hak"             ; but most are deprecated
               / "i-klingon"         ; in favor of more modern
               / "i-lux"             ; subtags or subtag
               / "i-mingo"           ; combination

               / "i-navajo"
               / "i-pwn"
               / "i-tao"
               / "i-tay"
               / "i-tsu"
               / "sgn-BE-FR"
               / "sgn-BE-NL"
               / "sgn-CH-DE"

 regular       = "art-lojban"        ; these tags match the 'langtag'
               / "cel-gaulish"       ; production, but their subtags
               / "no-bok"            ; are not extended language
               / "no-nyn"            ; or variant subtags: their meaning
               / "zh-guoyu"          ; is defined by their registration
               / "zh-hakka"          ; and all of these are deprecated
               / "zh-min"            ; in favor of a more modern
               / "zh-min-nan"        ; subtag or sequence of subtags
               / "zh-xiang"

 https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
bool is_language_tag(const std::string &str) {
	(void)str;
	// todo
	return true;
}

void skip_language_tag(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	(void)str;
	(void)start_pos;
	(void)end_pos;

	// todo
}

/*
 etagc = "!" / %x23-7E ; '#'-'~' / obs-text
 */
bool is_etag(char c) {
	return (c == '!' || ('#' <= c && c <= '~') || is_obs_text(c));
}

/*
 opaque-tag = DQUOTE *etagc DQUOTE
 */
bool is_opaque_tag(const std::string &str) {
	std::size_t pos;

	if (str.empty()) { return false; }

	pos = 0;
	if (str[pos] != '"') { return false; }
	pos++;

	while (str[pos] && is_etag(str[pos])) { pos++; }

	if (str[pos] != '"') { return false; }
	pos++;

	return pos == str.length();
}


/*
 entity-tag = [ weak ] opaque-tag
 weak = %x57.2F ; W/
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
bool is_entity_tag(const std::string &str) {
	std::size_t pos;

	if (str[0] != 'W' && str[0] != '"') { return false; }

	pos = 0;
	if (str[0] == 'W' && str[1] == '/') { pos += 2; }

	return is_opaque_tag(&str[pos]);
}

void skip_ows(const std::string &str, std::size_t *pos) {
	while (is_whitespace(str[*pos])) {
		*pos += 1;
	}
}

bool is_qdtext(char c) {
	if (c == HT || c == SP || c == 0x21) { return true; }
	if (0x23 <= c && c <= 0x5B) { return true; }
	if (0x5D <= c && c <= 0x7E) { return true; }
	if (is_obs_text(c)) { return true; }
	return false;
}

// hexadecimal 0-9/A-F/a-f
bool is_hexdig(char c) {
	return (('0' <= c && c <= '9')
			|| ('A' <= c && c <= 'F')
			|| ('a' <= c && c <= 'f'));
}

/*
 attr-char     = ALPHA / DIGIT
			   / "!" / "#" / "$" / "&" / "+" / "-" / "."
			   / "^" / "_" / "`" / "|" / "~"
			   ; token except ( "*" / "'" / "%" )
 https://www.rfc-editor.org/rfc/rfc5987.html#section-3.2
 */
bool is_attr_char(char c) {
	if (!is_tchar(c)) {
		return false;
	}
	if (c == '*' || c == '\'' || c == '%') {
		return false;
	}
	return true;
}

bool is_quoted_pair(const std::string &str, std::size_t pos) {
	if (str[pos] != '\\') { return false; }

	return (str[pos + 1] == HT
			|| str[pos + 1] == SP
			|| is_vchar(str[pos + 1])
			|| is_obs_text(str[pos + 1]));
}

/*
 pct-encoded   = "%" HEXDIG HEXDIG
			   ; see [RFC3986], Section 2.1
 https://www.rfc-editor.org/rfc/rfc3986#section-2.1
 */
bool is_pct_encoded(const std::string &str, std::size_t pos) {
	if (str.empty()) { return false; }
	return (str[pos] == '%'
			&& is_hexdig(str[pos + 1])
			&& is_hexdig(str[pos + 2]));
}

/*
 quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 */

void skip_quoted_string(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t len;

	if (!end_pos) { return; }

	*end_pos = start_pos;
	len = 0;

	if (str[start_pos + len] != '"') { return; }
	len += 1;

	while (str[start_pos + len]) {
		if (is_qdtext(str[start_pos + len])) {
			len += 1;
		} else if (is_quoted_pair(str, start_pos + len)) {
			len += 2;
		} else {
			return;
		}

		if (str[start_pos + len] == '"') {
			break;
		}
	}
	if (str[start_pos + len] != '"') {
		return;
	}
	++len;
	*end_pos = start_pos + len;
}

bool is_quoted_string(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) { return false; }

	pos = 0;
	skip_quoted_string(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_whitespace(char c) {
	return c == SP || c == HT;
}

bool is_end_with_cr(const std::string &str) {
	return (!str.empty() && str[str.length() - 1] == CR);
}

bool is_valid_method(const std::string &method) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(METHODS.begin(), METHODS.end(), method);
	return itr != METHODS.end();
}

bool is_valid_request_target(const std::string &request_target) {
	return HttpMessageParser::is_printable(request_target);
}

bool is_valid_http_version(const std::string &http_version) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(HTTP_VERSIONS.begin(), HTTP_VERSIONS.end(), http_version);
	return itr != HTTP_VERSIONS.end();
}

bool is_header_body_separator(const std::string &line_end_with_cr) {
	return line_end_with_cr == std::string(1, CR);
}

bool is_base_64_value_non_empty(const std::string &str) {
	char c;

	if (str.empty()) {
		return false;
	}
	for (size_t pos = 0; pos < str.length(); ++pos) {
		c = str[pos];
		if (std::isalnum(c) || c == '+' || c == '/' || c == '=') {
			continue;
		}
		return false;
	}
	return true;
}

/*
 absolute-URI  = scheme ":" hier-part [ "?" query ]

 hier-part     = "//" authority path-abempty
              / path-absolute
              / path-rootless
              / path-empty

 scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 path-rootless = segment-nz *( "/" segment )

 https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
 */
bool is_absolute_uri(const std::string &str) {
	(void)str;
	// todo
	return true;
}

/*
// partial-URI   = relative-part [ "?" query ]
// relative-part = "//" authority path-abempty
//                  / path-absolute
//                  / path-noscheme
//                  / path-empty

 authority   = [ userinfo "@" ] host [ ":" port ]

 query         = *( pchar / "/" / "?" )
 path-abempty  = *( "/" segment )

 path-absolute = "/" [ segment-nz *( "/" segment ) ]
 path-noscheme = segment-nz-nc *( "/" segment )
 path-empty    = 0<pchar>

 segment       = *pchar
 segment-nz    = 1*pchar
 pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

 unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
 reserved      = gen-delims / sub-delims
 gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
 sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
               / "*" / "+" / "," / ";" / "="

 pct-encoded = "%" HEXDIG HEXDIG; HEXDIG = hexadecimal digits

 https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
*/
bool is_partial_uri(const std::string &str) {
	(void)str;
	// todo
	return true;
}

std::string parse_uri_host(const std::string &str,
						   std::size_t start_pos,
						   std::size_t *end_pos) {
	(void)str;
	(void)start_pos;
	(void)end_pos;
	// todo
	return "";
}

std::string parse_port(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	(void)str;
	(void)start_pos;
	(void)end_pos;
	// todo
	return "";
}

}  // namespace HttpMessageParser
