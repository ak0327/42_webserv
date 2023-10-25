#include <ctype.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "Date.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"

namespace HttpMessageParser {


bool is_printable(const std::string &str)
{
	if (str.empty()) {
		return false;
	}

	for (size_t pos = 0; pos < str.length(); ++pos) {
		if (!isprint(str[pos])) {
			return false;
		}
	}
	return true;
}

// Delimiters : set of US-ASCII visual characters not allowed in a token
//  (DQUOTE and "(),/:;<=>?@[\]{}").
bool is_delimiters(char c) {
	return std::string(DELIMITERS).find(c) != std::string::npos;
}

// VCHAR = %x21-7E ; (any visible [USASCII] character).
bool is_vchar(char c) {
	return 0x21 <= c && c <= 0x7E;
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
// https://datatracker.ietf.org/doc/html/rfc7230#ref-USASCII
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

// ctext = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
bool is_ctext(char c) {
	return (is_whitespace(c)
			|| (0x21 <= c && c <= 0x27)
			|| (0x2A <= c && c <= 0x5B)
			|| (0x5D <= c && c <= 0x7E)
			|| is_obs_text(c));
}

// token = 1*tchar
bool is_token(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}

	skip_token(str, 0, &end);
	return str[end] == '\0';
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
bool is_ext_token(const std::string &str) {
	std::size_t pos;

	if (str.empty()) { return false; }
	pos = 0;
	while (str[pos] && HttpMessageParser::is_tchar(str[pos])) {
		++pos;
	}
	if (pos < 2 || str[pos - 1] != '*') {
		return false;
	}
	return str[pos] == '\0';
}

/*
 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]
 */
bool is_langtag(const std::string &str) {
	std::size_t pos, end;

	pos = 0;
	skip_langtag(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

/*
 privateuse    = "x" 1*("-" (1*8alphanum))
 */
bool is_privateuse(const std::string &str) {
	std::size_t pos, end;

	pos = 0;
	skip_privateuse(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

/*
 grandfathered = irregular           ; non-redundant tags registered
               / regular             ; during the RFC 3066 era
 https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
bool is_grandfathered(const std::string &str) {
	return (is_irregular(str) || is_regular(str));
}

/*
 Language-Tag  = langtag             ; normal language tags
               / privateuse          ; private use tag
               / grandfathered       ; grandfathered tags
  https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
bool is_language_tag(const std::string &str) {
	return (is_langtag(str)
			|| is_privateuse(str)
			|| is_grandfathered(str));
}

bool is_language(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	skip_language(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_script(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	skip_script(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_region(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	skip_region(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_variant(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	skip_variant(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_extension(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	skip_extension(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;
	return str[pos] == '\0';
}

bool is_langtag_option(const std::string &str,
					   std::size_t start_pos,
					   void (*skip_func)(const std::string &,
										 std::size_t,
										 std::size_t *)) {
	std::size_t pos, end;

	if (str.empty() || str.length() <= start_pos) { return false; }

	pos = start_pos;
	if (str[pos] != '-') { return false; }
	++pos;

	skip_func(str, pos, &end);
	return pos != end;
}

/*
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
 */
bool is_irregular(const std::string &str) {
	return ((str == "en-GB-oed")
			|| (str == "i-ami")
			|| (str == "i-bnn")
			|| (str == "i-default")
			|| (str == "i-enochian")
			|| (str == "i-hak")
			|| (str == "i-klingon")
			|| (str == "i-lux")
			|| (str == "i-mingo")
			|| (str == "i-navajo")
			|| (str == "i-pwn")
			|| (str == "i-tao")
			|| (str == "i-tay")
			|| (str == "i-tsu")
			|| (str == "sgn-BE-FR")
			|| (str == "sgn-BE-NL")
			|| (str == "sgn-CH-DE"));
}

/*
 regular       = "art-lojban"        ; these tags match the 'langtag'
               / "cel-gaulish"       ; production, but their subtags
               / "no-bok"            ; are not extended language
               / "no-nyn"            ; or variant subtags: their meaning
               / "zh-guoyu"          ; is defined by their registration
               / "zh-hakka"          ; and all of these are deprecated
               / "zh-min"            ; in favor of a more modern
               / "zh-min-nan"        ; subtag or sequence of subtags
               / "zh-xiang"
 */
bool is_regular(const std::string &str) {
	return ((str == "art-lojban")
			|| (str == "cel-gaulish")
			|| (str == "no-bok")
			|| (str == "no-nyn")
			|| (str == "zh-guoyu")
			|| (str == "zh-hakka")
			|| (str == "zh-min")
			|| (str == "zh-min-nan")
			|| (str == "zh-xiang"));
}


// etagc = "!" / %x23-7E ; '#'-'~' / obs-text
bool is_etag(char c) {
	return (c == '!' || ('#' <= c && c <= '~') || is_obs_text(c));
}

// opaque-tag = DQUOTE *etagc DQUOTE
bool is_opaque_tag(const std::string &str) {
	std::size_t pos;

	if (str.empty()) {
		return false;
	}

	pos = 0;
	if (str[pos] != '"') {
		return false;
	}
	pos++;

	while (str[pos] && is_etag(str[pos])) {
		pos++;
	}

	if (str[pos] != '"') {
		return false;
	}
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

	if (str[0] != 'W' && str[0] != '"') {
		return false;
	}

	pos = 0;
	if (str[0] == 'W' && str[1] == '/') {
		pos += 2;
	}

	return is_opaque_tag(&str[pos]);
}

/*
 dtext           =   %d33-90 /          ; Printable US-ASCII
                     %d94-126 /         ;  characters not including
                     obs-dtext          ;  "[", "]", or "\"
 */
bool is_obs_dtext(char c) {
	return (c == '[' || c == ']' || c == '\\');
}

bool is_dtext(char c) {
	if (33 <= c && c <= 90) {
		return true;
	}
	if (94 <= c && c <= 126) {
		return true;
	}
	if (is_obs_dtext(c)) {
		return true;
	}
	return false;
}

bool is_qdtext(char c) {
	if (c == HT || c == SP || c == 0x21) {
		return true;
	}
	if (0x23 <= c && c <= 0x5B) {
		return true;
	}
	if (0x5D <= c && c <= 0x7E) {
		return true;
	}
	if (is_obs_text(c)) {
		return true;
	}
	return false;
}

// HEXDIG (hexadecimal digits) 0-9/A-F/a-f
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

/*
 singleton     = DIGIT               ; 0 - 9
               / %x41-57             ; A - W
               / %x59-5A             ; Y - Z
               / %x61-77             ; a - w
               / %x79-7A             ; y - z
 */
bool is_singleton(char c) {
	if (!std::isalnum(c)) {
		return false;
	}
	if (c == 'X' || c == 'x') {
		return false;
	}
	return true;
}

// todo: rm start_pos?, use skip_quoted_pair?
bool is_quoted_pair(const std::string &str, std::size_t start_pos) {
	if (str.empty() || str.length() <= start_pos) {
		return false;
	}
	if (str[start_pos] != '\\') {
		return false;
	}

	return (str[start_pos + 1] == HT
			|| str[start_pos + 1] == SP
			|| is_vchar(str[start_pos + 1])
			|| is_obs_text(str[start_pos + 1]));
}

/*
 quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
 */
void skip_quoted_pair(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	if (!is_quoted_pair(str, start_pos)) {
		return;
	}
	*end_pos = start_pos + 2;
}

/*
 pct-encoded   = "%" HEXDIG HEXDIG
			   ; see [RFC3986], Section 2.1
 https://www.rfc-editor.org/rfc/rfc3986#section-2.1
 */
bool is_pct_encoded(const std::string &str, std::size_t start_pos) {
	std::size_t end;

	if (str.empty() || str.length() <= start_pos) {
		return false;
	}
	skip_pct_encoded(str, start_pos, &end);
	return str[end] == '\0';
}

// todo: test
bool is_http_date(const std::string &str) {
	Date date = Date(str);
	return date.is_ok();
}

bool is_quoted_string(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}

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
	if (request_target.empty()) {
		return false;
	}
	return HttpMessageParser::is_printable(request_target);
}

bool is_valid_http_version(const std::string &http_version) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(HTTP_VERSIONS.begin(), HTTP_VERSIONS.end(), http_version);
	return itr != HTTP_VERSIONS.end();
}

bool is_valid_field_name(const std::string &field_name) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(FIELD_NAMES.begin(), FIELD_NAMES.end(), field_name);
	return itr != FIELD_NAMES.end();
}

// field-name = token
bool is_valid_field_name_syntax(const std::string &field_name) {
	return HttpMessageParser::is_token(field_name);
}

// field-value = *( field-content )  // todo: empty??
bool is_valid_field_value_syntax(const std::string &field_value) {
	if (field_value.empty()) {
		return false;
	}
	if (!HttpMessageParser::is_field_content(field_value)) {
		return false;
	}
	return true;
}

bool is_ignore_field_name(const std::string &field_name) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(IGNORE_HEADERS.begin(), IGNORE_HEADERS.end(), field_name);
	return itr != IGNORE_HEADERS.end();
}

bool is_header_body_separator(const std::string &line_end_with_cr) {
	return line_end_with_cr == std::string(1, CR);
}

// todo: test
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
 pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
 segment       = *pchar
 segment-nz    = 1*pchar
 segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
               ; non-zero-length segment without any colon ":"
 */
bool is_pchar(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_pchar(str, 0, &end);
	return str[end] == '\0';
}

bool is_segment(const std::string &str) {
	std::size_t end;

	skip_segment(str, 0, &end);
	return str[end] == '\0';
}

bool is_segment_nz(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_segment_nz(str, 0, &end);
	return str[end] == '\0';
}

bool is_segment_nz_nc(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_segment_nz_nc(str, 0, &end);
	return str[end] == '\0';
}

/*
 path-abempty  = *( "/" segment )
 path-absolute = "/" [ segment-nz *( "/" segment ) ]
 path-noscheme = segment-nz-nc *( "/" segment )
 path-rootless = segment-nz *( "/" segment )
 path-empty    = 0<pchar>
 */
bool is_path_abempty(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_path_abempty(str, 0, &end);
	return str[end] == '\0';
}

bool is_path_absolute(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_path_absolute(str, 0, &end);
	return str[end] == '\0';
}

bool is_path_noscheme(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_path_noscheme(str, 0, &end);
	return str[end] == '\0';
}

bool is_path_rootless(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_path_rootless(str, 0, &end);
	return str[end] == '\0';
}

// path-empty = 0<pchar>
bool is_path_empty(const std::string &str, std::size_t start_pos) {
	std::size_t pos, end;
	pos = start_pos;
	if (str.length() < start_pos) {
		return false;
	}
	skip_pchar(str, pos, &end);
	return pos == end;
}

bool is_userinfo(const std::string &str) {
	std::size_t end;

	skip_userinfo(str, 0, &end);
	return str[end] == '\0';
}

bool is_authority(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_authority(str, 0, &end);
	return str[end] == '\0';
}

// query = *( pchar / "/" / "?" )
bool is_query(const std::string &str) {
	std::size_t end;
	if (str.empty()) {
		return false;
	}
	skip_query(str, 0, &end);
	return str[end] == '\0';
}

/*
 absolute-URI  = scheme ":" hier-part [ "?" query ]
 https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
 */
bool is_absolute_uri(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_absolute_uri(str, 0, &end);
	return str[end] == '\0';
}

// partial-URI = relative-part [ "?" query ]
bool is_partial_uri(const std::string &str) {
	std::size_t end;

	skip_partial_uri(str, 0, &end);
	return str[end] == '\0';
}

bool is_ipv6address(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipv6address(str, 0, &end);
	return str[end] == '\0';
}

// IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
bool is_ipvfuture(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipvfuture(str, 0, &end);
	return str[end] == '\0';
}

// todo:test(ipv6)
bool is_ip_literal(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ip_literal(str, 0, &end);
	return str[end] == '\0';
}

bool is_dec_octet(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_dec_octet(str, 0, &end);
	return str[end] == '\0';
}

bool is_ipv4address(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipv4address(str, 0, &end);
	return str[end] == '\0';
}

// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
bool is_unreserved(char c) {
	return (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~');
}

// sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
bool is_sub_delims(char c) {
	return std::string(SUB_DELIMS).find(c) != std::string::npos;
}

bool is_reg_name(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_reg_name(str, 0, &end);
	return str[end] == '\0';
}

bool is_uri_host(const std::string &uri_host) {
	return (HttpMessageParser::is_ip_literal(uri_host)
			|| HttpMessageParser::is_ipv4address(uri_host)
			|| HttpMessageParser::is_reg_name(uri_host));
}

bool is_port(const std::string &port) {
	int port_num;
	bool succeed;

	port_num = HttpMessageParser::to_integer_num(port, &succeed);
	return (succeed && (PORT_MIN <= port_num && port_num <= PORT_MAX));
}

// scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
bool is_scheme(const std::string &scheme) {
	std::size_t pos, end;

	if (scheme.empty() || !std::isalpha(scheme[0])) {
		return false;
	}
	pos = 1;
	skip_scheme(scheme, pos, &end);
	return scheme[end] == '\0';
}

// type = token
bool is_valid_type(const std::string &type) {
	return HttpMessageParser::is_token(type);
}

// subtype = token
bool is_valid_subtype(const std::string &subtype) {
	return HttpMessageParser::is_token(subtype);
}

/*
 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
bool is_valid_parameters(const std::map<std::string, std::string> &parameters) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string parameter_name, parameter_value;

	for (itr = parameters.begin(); itr != parameters.end(); ++itr) {
		parameter_name = itr->first;
		parameter_value = itr->second;

		if (!HttpMessageParser::is_token(parameter_name)) {
			return false;
		}
		if (!HttpMessageParser::is_token(parameter_value)
			&& !HttpMessageParser::is_quoted_string(parameter_value)) {
			return false;
		}
	}
	return true;
}

bool is_parameter_weight(const std::string &parameter_name,
						 const std::string &parameter_value) {
	bool succeed;

	if (parameter_name != "q") {
		return false;
	}
	HttpMessageParser::to_floating_num(parameter_value, 3, &succeed);
	return succeed;
}

bool is_parameter_weight(const std::string &parameter_name) {
	return parameter_name == "q";
}

bool is_mailbox(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_mailbox(str, 0, &end);
	return str[end] == '\0';
}

/*
 atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
                     "!" / "#" /        ;  characters not including
                     "$" / "%" /        ;  specials.  Used for atoms.
                     "&" / "'" /
                     "*" / "+" /
                     "-" / "/" /
                     "=" / "?" /
                     "^" / "_" /
                     "`" / "{" /
                     "|" / "}" /
                     "~"
 */
bool is_atext(char c) {
	const std::string atext_except_alnum = "!#$%&'*+-/=?^_`{|}~";

	if (std::isalnum(c)) {
		return true;
	}
	return (atext_except_alnum.find(c) != std::string::npos);
}

// atom = [CFWS] 1*atext [CFWS] -> 1*atext
bool is_atom(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_atom(str, 0, &end);
	return str[end] == '\0';
}


}  // namespace HttpMessageParser
