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

/*
 extlang       = 3ALPHA              ; selected ISO 639 codes
                 *2("-" 3ALPHA)      ; permanently reserved
 */
void skip_extlang(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, tmp_pos, len, cnt;
	const int alpha_len = 3;
	const int repeat_min = 2;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (len != alpha_len) { return; }
	pos += len;

	cnt = 0;
	while (str[pos]) {
		if (str[pos] != '-') { break; }  // Followed by a non-extlang string

		len = 0;
		tmp_pos = pos + 1;
		while (str[tmp_pos + len] && std::isalpha(str[tmp_pos + len])) {
			++len;
		}
		if (len != alpha_len) {
			break;
		}
		pos = tmp_pos + len;
		++cnt;
		if (cnt == repeat_min) {
			break;
		}
	}

	*end_pos = pos;
}

/*
 language      = 2*3ALPHA            ; shortest ISO 639 code
                 ["-" extlang]       ; sometimes followed by
                                     ; extended language subtags
               / 4ALPHA              ; or reserved for future use
               / 5*8ALPHA            ; or registered language subtag
 */
void skip_language(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos) {
	std::size_t pos, end, len;
	const int shortest_code_min = 2;
	const int shortest_code_max = 3;
	const int reserved_len = 4;
	const int registered_min = 5;
	const int registered_max = 8;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (shortest_code_min <= len && len <= shortest_code_max) {
		pos += len;
		if (str[pos] == '-') {
			skip_extlang(str, pos + 1, &end);
			if (pos + 1 != end) {
				pos = end;
			}
		}
	} else if (len == reserved_len
			|| (registered_min <= len && len <= registered_max)) {
		pos += len;
	} else {
		return;
	}
	*end_pos = pos;
}

/*
 script = 4ALPHA ; ISO 15924 code
 */
void skip_script(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos) {
	std::size_t pos, len;
	const int script_len = 4;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (len != script_len) { return; }
	pos += len;
	*end_pos = pos;
}

/*
 region        = 2ALPHA              ; ISO 3166-1 code
               / 3DIGIT              ; UN M.49 code
 */
void skip_region(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos) {
	std::size_t pos, len;
	const int alpha_len = 2;
	const int digit_len = 3;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	if (std::isalpha(str[pos])) {
		while (str[pos + len] && std::isalpha(str[pos + len])) {
			++len;
		}
		if (len != alpha_len) { return; }
		pos += len;
	} else if (std::isdigit(str[pos])) {
		while (str[pos + len] && std::isdigit(str[pos + len])) {
			++len;
		}
		if (len != digit_len) { return; }
		pos += len;
	} else {
		return;
	}
	*end_pos = pos;
}

/*
 variant       = 5*8alphanum         ; registered variants
               / (DIGIT 3alphanum)
 */
void skip_variant(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, tmp_pos, len1, len2;
	const int alnum_min = 5;
	const int alnum_max = 8;
	const int digit_len = 3;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;

	// 5*8alphanum
	len1 = 0;
	if (std::isalnum(str[pos])) {
		while (str[pos + len1] && std::isalnum(str[pos + len1])) {
			++len1;
		}
	}

	// DIGIT 3alphanum
	len2 = 0;
	if (std::isdigit(str[pos])) {
		tmp_pos = pos + 1;
		while (str[tmp_pos + len2] && std::isalnum(str[tmp_pos + len2])) {
			++len2;
		}
	}

	if (alnum_min <= len1 && len1 <= alnum_max) {
		pos += len1;
	} else if (len2 == digit_len) {
		pos = tmp_pos + len2;
	} else {
		return;
	}
	*end_pos = pos;
}

/*
 extension     = singleton 1*("-" (2*8alphanum))
 singleton     = DIGIT               ; 0 - 9
               / %x41-57             ; A - W
               / %x59-5A             ; Y - Z
               / %x61-77             ; a - w
               / %x79-7A             ; y - z
 */
void skip_extension(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t pos, tmp_pos, len, cnt;
	const int alnum_min = 2;
	const int alnum_max = 8;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	if (!is_singleton(str[pos])) { return; }
	++pos;

	cnt = 0;
	while (true) {
		if (str[pos] != '-') { break; }

		len = 0;
		tmp_pos = pos + 1;
		while (str[tmp_pos + len] && std::isalnum(str[tmp_pos + len])) {
			++len;
		}
		if (len < alnum_min || alnum_max < len) { break; }
		pos = tmp_pos + len;
		++cnt;
	}

	if (cnt == 0) {
		return;
	}
	*end_pos = pos;
}

/*
 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]
 */
void skip_langtag(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, end;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	// language
	pos = start_pos;
	skip_language(str, pos, &end);
	if (pos == end) { return; }
	pos = end;

	// ["-" script]
	if (is_langtag_option(str, pos, skip_script)) {
		++pos;
		skip_script(str, pos, &end);
		// std::cout << CYAN << "script" << RESET << std::endl;
		pos = end;
	}

	// ["-" region]
	if (is_langtag_option(str, pos, skip_region)) {
		++pos;
		skip_region(str, pos, &end);
		// std::cout << CYAN << "region" << RESET << std::endl;
		pos = end;
	}

	// *("-" variant)
	while (str[pos]) {
		if (is_langtag_option(str, pos, skip_variant)) {
			++pos;
			skip_variant(str, pos, &end);
			// std::cout << CYAN << "variant" << RESET << std::endl;
			pos = end;
			continue;
		}
		break;
	}

	// *("-" extension)
	while (str[pos]) {
		if (is_langtag_option(str, pos, skip_extension)) {
			++pos;
			skip_extension(str, pos, &end);
			// std::cout << CYAN << "extension" << RESET << std::endl;
			pos = end;
			continue;
		}
		break;
	}

	// ["-" privateuse]
	if (is_langtag_option(str, pos, skip_privateuse)) {
		++pos;
		skip_privateuse(str, pos, &end);
		// std::cout << CYAN << "privateuse" << RESET << std::endl;
		pos = end;
	}

	*end_pos = pos;
}

/*
 privateuse    = "x" 1*("-" (1*8alphanum))
 */
void skip_privateuse(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos) {
	std::size_t pos, tmp_pos, len, cnt;
	const int alnum_min = 1;
	const int alnum_max = 8;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	pos = start_pos;
	if (str[pos] != 'x') {
		return;
	}
	++pos;

	cnt = 0;
	while (str[pos]) {
		if (str[pos] != '-') { break; }

		len = 0;
		tmp_pos = pos + 1;
		while (str[tmp_pos + len]
			   && std::isalnum(str[tmp_pos + len])) {
			len++;
		}
		if (len < alnum_min || alnum_max < len) {
			break;
		}
		pos = tmp_pos + len;
		++cnt;
	}
	if (cnt == 0) {
		return;
	}
	*end_pos = pos;
}

/*
 grandfathered = irregular           ; non-redundant tags registered
               / regular             ; during the RFC 3066 era
 https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
// todo: test
void skip_grandfathered(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, len;
	std::string value;

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len]
		   && !is_delimiters(str[pos + len])
		   && !is_whitespace(str[pos + len])) {
		++len;
	}
	value = str.substr(pos, len);
	if (!is_irregular(value) && !is_regular(value)) {
		return;
	}
	*end_pos = pos + len;
}

/*
 Language-Tag  = langtag             ; normal language tags
               / privateuse          ; private use tag
               / grandfathered       ; grandfathered tags
  https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
void skip_language_tag(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	skip_grandfathered(str, start_pos, end_pos);
	if (start_pos != *end_pos) {
		return;
	}

	skip_privateuse(str, start_pos, end_pos);
	if (start_pos != *end_pos) {
		return;
	}

	skip_langtag(str, start_pos, end_pos);
	if (start_pos != *end_pos) {
		return;
	}
}

void skip_ows(const std::string &str, std::size_t *pos) {
	if (!pos) { return; }
	if (str.empty() || str.length() <= *pos) {
		return;
	}

	while (is_whitespace(str[*pos])) {
		*pos += 1;
	}
}

void skip_pct_encoded(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	std::size_t pos, len;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() < start_pos) {
		return;
	}

	len = 0;
	while (str[pos + len]) {
		if (str[pos + len] == '%'
			&& is_hexdig(str[pos + len + 1])
			&& is_hexdig(str[pos + len + 2])) {
			len += 3;
			continue;
		}
		break;
	}
	if (len == 0) {
		return;
	}
	pos += len;
	*end_pos = pos;
}

// todo:test
void skip_token_or_quoted_string(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos) {
	std::size_t end;

	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return;
	}

	end = start_pos;
	if (HttpMessageParser::is_tchar(field_value[start_pos])) {
		skip_token(field_value, start_pos, &end);
	} else if (field_value[start_pos] == '"') {
		HttpMessageParser::skip_quoted_string(field_value, start_pos, &end);
	}
	*end_pos = end;
}

// todo:test
void skip_token(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos) {
	std::size_t pos;

	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.length() <= start_pos) {
		return;
	}

	pos = start_pos;
	while (str[pos] && is_tchar(str[pos])) {
		++pos;
	}
	*end_pos = pos;
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

	if (!end_pos) {
		return;
	}
	if (str.length() <= start_pos) {
		return;
	}

	*end_pos = start_pos;
	len = 0;

	if (str[start_pos + len] != '"') {
		return;
	}
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

// userinfo  = *( unreserved / pct-encoded / sub-delims / ":" )
void skip_userinfo(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.length() <= start_pos) {
		return;
	}
	while (str[pos]) {
		if (is_unreserved(str[pos])
			|| is_sub_delims(str[pos])
			|| str[pos] == ':') {
			++pos;
			continue;
		}
		skip_pct_encoded(str, pos, &end);
		if (pos != end) {
			pos = end;
			continue;
		}
		break;
	}
	*end_pos = pos;
}

// authority = [ userinfo "@" ] host [ ":" port ]
void skip_authority(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	skip_userinfo(str, pos, &end);
	if (pos != end && str[end] == '@') {
		pos = end + 1;
	}

	skip_uri_host(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;

	if (str[pos] != ':') {
		*end_pos = pos;
		return;
	}
	++pos;

	skip_port(str, pos, &end);
	if (pos == end) {
		return;
	}
	*end_pos = end;
}

// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
void skip_pchar(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	if (is_unreserved(str[pos])
		|| is_sub_delims(str[pos])
		|| str[pos] == ':' || str[pos] == '@') {
		++pos;
	} else{
		skip_pct_encoded(str, pos, &end);
		if (pos == end) {
			return;
		}
		pos = end;
	}
	*end_pos = pos;
}

// segment = *pchar
void skip_segment(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.length() <= start_pos) {
		return;
	}

	while (str[pos]) {
		skip_pchar(str, pos, &end);
		if (pos == end) {
			break;
		}
		pos = end;
	}
	*end_pos = end;
}

// path-abempty = *( "/" segment )
void skip_path_abempty(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	while (str[pos]) {
		if (str[pos] != '/') {
			break;
		}
		skip_segment(str, pos + 1, &end);
		pos = end;
	}
	*end_pos = pos;
}

// path-absolute = "/" [ segment-nz *( "/" segment ) ]
void skip_path_absolute(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	if (str[pos] != '/') {
		return;
	}
	++pos;
	*end_pos = pos;

	skip_segment_nz(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;
	skip_path_abempty(str, pos, &end);
	*end_pos = end;
}

// path-noscheme = segment-nz-nc *( "/" segment )
void skip_path_noscheme(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	skip_segment_nz_nc(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;
	skip_path_abempty(str, pos, &end);
	*end_pos = end;
}

// path-rootless = segment-nz *( "/" segment )
void skip_path_rootless(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	skip_segment_nz(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;
	skip_path_abempty(str, pos, &end);
	*end_pos = end;
}

// segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
void skip_segment_nz_nc(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	pos = start_pos;
	while (str[pos]) {
		if (is_unreserved(str[pos])
			|| is_sub_delims(str[pos])
			|| str[pos] == '@') {
			++pos;
			continue;
		}
		skip_pct_encoded(str, pos, &end);
		if (pos != end) {
			pos = end;
			continue;
		}
		break;
	}
	if (start_pos == pos) {
		return;
	}
	*end_pos = pos;
}

// segment-nz = 1*pchar
void skip_segment_nz(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	pos = start_pos;
	while (str[pos]) {
		skip_pchar(str, pos, &end);
		if (pos == end) {
			break;
		}
		pos = end;
	}
	if (start_pos == pos) {
		return;
	}
	*end_pos = pos;
}

/*
 relative-part = "//" authority path-abempty
                  / path-absolute
                  / path-noscheme
                  / path-empty
 */
void skip_relative_part(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;

	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	if (str[pos] == '/' && str[pos + 1] == '/') {
		pos += 2;
		skip_authority(str, pos, &end);
		if (pos == end) { return; }
		skip_path_abempty(str, end, &end);
	} else if (str[pos] == '/' && str[pos + 1] != '/') {
		skip_path_absolute(str, pos, &end);
	} else {
		skip_path_noscheme(str, pos, &end);
	}
	if (pos == end) {
		return;
	}
	*end_pos = end;
}

/*
 hier-part = "//" authority path-abempty
           / path-absolute
           / path-rootless
           / path-empty
 */
void skip_hier_part(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	if (str[pos] == '/' && str[pos + 1] == '/') {
		pos += 2;
		skip_authority(str, pos, &end);
		if (pos == end) { return; }
		skip_path_abempty(str, end, &end);
	} else if (str[pos] == '/' && str[pos + 1] != '/') {
		skip_path_absolute(str, pos, &end);
	} else {
		skip_path_rootless(str, pos, &end);
	}

	if (pos == end) {
		return;
	}
	*end_pos = end;
}

// query = *( pchar / "/" / "?" )
void skip_query(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	while (str[pos]) {
		skip_pchar(str, pos, &end);
		if (pos != end) {
			pos = end;
			continue;
		}
		if (str[pos] == '/' || str[pos] == '?') {
			++pos;
			continue;
		}
		break;
	}
	*end_pos = pos;
}

// fragment = *( pchar / "/" / "?" )
void skip_fragment(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos) {
	return skip_query(str, start_pos, end_pos);
}

// todo: test
// absolute-URI  = scheme ":" hier-part [ "?" query ]
void skip_absolute_uri(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}

	// scheme
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	skip_scheme(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;

	// ":"
	if (str[pos] != ':') {
		return;
	}
	++pos;

	// hier-part
	skip_hier_part(str, pos, &end);
	pos = end;  // if (pos == end) -> path-empty

	// [ ? query ]
	if (str[pos] == '?') {
		skip_query(str, pos + 1, &end);
		pos = end;
	}
	*end_pos = pos;
}

/*
 partial-URI = relative-part [ "?" query ]
 https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
*/
void skip_partial_uri(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) {
		return;
	}

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}

	skip_relative_part(str, pos, &end);
	pos = end;  // if (pos == end) -> path-empty

	// [ ? query ]
	if (str[pos] == '?') {
		skip_query(str, pos + 1, &end);
		pos = end;
	}
	*end_pos = end;
}

/*
 product         = token ["/" product-version]
 product-version = token
 */
void skip_product(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, len;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	len = 0;
	while (HttpMessageParser::is_tchar(str[pos + len])) {
		++len;
	}
	if (len == 0) { return; }
	pos += len;

	if (str[pos] != '/') {
		*end_pos = pos; return; }

	// ["/" product-version]
	++pos;
	len = 0;
	while (HttpMessageParser::is_tchar(str[pos + len])) {
		++len;
	}
	if (len == 0) { return; }
	pos += len;
	*end_pos = pos;
}

/*
 comment  = "(" *( ctext / quoted-pair / comment ) ")"
 ctext    = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
 https://www.rfc-editor.org/rfc/rfc9110#name-comments
 */
void skip_comment(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, len, end;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	if (str[pos] != '(') { return; }
	++pos;

	len = 0;
	while (str[pos + len]) {
		if (HttpMessageParser::is_ctext(str[pos + len])) {
			while (str[pos + len]
				   && HttpMessageParser::is_ctext(str[pos + len])) {
				++len;
			}
		}
		if (HttpMessageParser::is_quoted_pair(str, pos + len)) {
			HttpMessageParser::skip_quoted_pair(str, pos + len, &end);
			if (pos + len == end) { return; }
			len += end - (pos + len);
		}
		if (str[pos + len] == '(') {
			skip_comment(str, pos + len, &end);
			if (pos + len == end) { return; }
			len += end - (pos + len);
		}
		if (str[pos + len] == ')') {
			break;
		}
	}

	if (len == 0) { return; }
	pos += len;

	if (str[pos] != ')') { return; }
	++pos;

	*end_pos = pos;
}

// h16 = 1*4HEXDIG
void skip_h16(const std::string &str,
			  std::size_t start_pos,
			  std::size_t *end_pos) {
	std::size_t pos, len;
	const int hexdig_min = 1;
	const int hexdig_max = 4;

	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	len = 0;
	while (str[pos + len] && is_hexdig(str[pos + len])) {
		++len;
		if (len == hexdig_max) {
			break;
		}
	}
	if (len < hexdig_min) {
		return;
	}
	pos += len;
	*end_pos = pos;
}

// ls32 = ( h16 ":" h16 ) / IPv4address
void skip_ls32(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	// IPv4address
	skip_ipv4address(str, pos, &end);
	if (pos != end) {
		*end_pos = end;
		return;
	}

	// ( h16 ":" h16 )
	skip_h16(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;

	if (str[pos] != ':') {
		return;
	}
	++pos;

	skip_h16(str, pos, &end);
	if (pos == end) {
		return;
	}
	pos = end;

	*end_pos = pos;
}

// todo: test
/*
 IPv6address =                            6( h16 ":" ) ls32
             /                       "::" 5( h16 ":" ) ls32
             / [               h16 ] "::" 4( h16 ":" ) ls32
             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
             / [ *4( h16 ":" ) h16 ] "::"              ls32
             / [ *5( h16 ":" ) h16 ] "::"              h16
             / [ *6( h16 ":" ) h16 ] "::"
 */
void skip_ipv6address(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	std::size_t pos, end, double_colon_pos, cnt;
	Result<std::size_t, int> double_colon_result;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	double_colon_result = get_double_colon_pos(str, pos);
	if (double_colon_result.is_err()) {
		// 6( h16 ":" )
		cnt = 0;
		while (str[pos] && cnt < 6) {
			skip_h16(str, pos, &end);
			if (pos == end) {
				return;
			}
			pos = end;
			if (str[pos] != ':') {
				return;
			}
			++pos;
			++cnt;
		}
		if (cnt != 6) {
			return;
		}

		// ls32
		skip_ls32(str, pos, &end);
		if (pos == end) {
			return;
		}
		pos = end;

	} else {
		double_colon_pos = double_colon_result.get_ok_value();
		(void)double_colon_pos;
		// todo
	}

	*end_pos = pos;
}

void skip_ipvfuture(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t pos, len;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	if (!(str[pos] == 'v' && is_hexdig(str[pos + 1]) && str[pos + 2] == '.')) {
		return;
	}
	pos += 3;
	len = 0;
	while (str[pos + len]
		   && (is_unreserved(str[pos + len])
			   || is_sub_delims(str[pos + len])
			   || str[pos + len] == ':')) {
		++len;
	}
	if (len == 0) {
		return;
	}
	pos += len;
	*end_pos = pos;
}

// todo:test(ipv6)
void skip_ip_literal(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos) {
	std::size_t pos, end;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	if (str[pos] != '[') {
		return;
	}
	++pos;

	if (str[pos] == 'v') {
		skip_ipvfuture(str, pos, &end);
	} else {
		skip_ipv6address(str, pos, &end);
	}
	if (pos == end) {
		return;
	}
	pos = end;

	if (str[pos] != ']') {
		return;
	}
	++pos;
	*end_pos = pos;
}

/*
 dec-octet = DIGIT                 ; 0-9
           / %x31-39 DIGIT         ; 10-99
           / "1" 2DIGIT            ; 100-199
           / "2" %x30-34 DIGIT     ; 200-249
           / "25" %x30-35          ; 250-255
 */
void skip_dec_octet(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t len;
	std::string digit_str;
	int num;

	if (!end_pos) { return; }

	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	len = 0;
	while (std::isdigit(str[start_pos + len])) {
		++len;
	}
	if (len < 1 || 3 < len) { return; }
	digit_str = str.substr(start_pos, len);

	if (digit_str[0] == '0' && len != 1) { return; }

	num = to_integer_num(digit_str, NULL);
	if (num < 0 || 255 < num) { return; }
	*end_pos = start_pos + len;
}

// IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
void skip_ipv4address(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	std::size_t pos, end, cnt;
	const int dec_octet_cnt = 4;

	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	cnt = 0;
	while (str[pos] && cnt < dec_octet_cnt) {
		skip_dec_octet(str, pos, &end);
		if (pos == end) { return; }
		pos = end;
		++cnt;
		if (cnt < dec_octet_cnt) {
			if (str[pos] != '.') { return; }
			++pos;
		}
	}
	if (cnt != dec_octet_cnt) { return; }
	*end_pos = pos;
}

// reg-name = *( unreserved / pct-encoded / sub-delims )
void skip_reg_name(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos) {
	std::size_t pos, len;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	len = 0;
	while (str[pos + len]) {
		if (is_unreserved(str[pos + len])
			|| is_sub_delims(str[pos + len])) {
			++len;
		} else if (is_pct_encoded(str, pos + len)) {
			len += 3;
		} else {
			break;
		}
	}
	if (len == 0) { return; }
	pos += len;
	*end_pos = pos;
}

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
void skip_uri_host(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos) {
	std::size_t pos, end, len;

	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() < start_pos) {
		return;
	}

	if (str[pos] == '[') {
		HttpMessageParser::skip_ip_literal(str, pos, &end);
	} else if (std::isdigit(str[pos])) {
		HttpMessageParser::skip_ipv4address(str, pos, &end);
	} else if (HttpMessageParser::is_unreserved(str[pos])
			   || str[pos] == '%'
			   || HttpMessageParser::is_sub_delims(str[pos])) {
		HttpMessageParser::skip_reg_name(str, pos, &end);
	} else {
		return;
	}

	if (pos == end) {
		return;
	}
	len = end - pos;
	pos += len;

	*end_pos = pos;
}

// port = *DIGIT
void skip_port(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos) {
	std::size_t pos, len;
	std::string port;

	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.empty() || str.length() < start_pos) {
		return;
	}

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isdigit(str[pos + len])) {
		++len;
	}
	if (len == 0) {
		return;
	}
	pos += len;
	*end_pos = pos;
}

// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
void skip_scheme(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos) {
	std::size_t pos;

	if (!end_pos) {
		return;
	}
	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	if (str.empty() || !std::isalpha(str[0])) {
		return;
	}
	pos = 1;
	while (str[pos]) {
		if (std::isalnum(str[pos])
			|| str[pos] == '+'
			|| str[pos] == '-'
			|| str[pos] == '.') {
			++pos;
			continue;
		}
		break;
	}
	*end_pos = pos;
}

Result<std::size_t, int> skip_ows_delimiter_ows(const std::string &field_value,
												char delimiter,
												std::size_t start_pos) {
	std::size_t pos;

	if (field_value.length() < start_pos) {
		return Result<std::size_t, int>::err(ERR);
	}
	pos = start_pos;

	if (field_value[pos] == '\0') {
		return Result<std::size_t, int>::ok(pos);
	}

	HttpMessageParser::skip_ows(field_value, &pos);
	if (field_value[pos] != delimiter) {
		return Result<std::size_t, int>::err(ERR);
	}
	++pos;
	HttpMessageParser::skip_ows(field_value, &pos);
	if (field_value[pos] == '\0') {
		return Result<std::size_t, int>::err(ERR);
	}
	return Result<std::size_t, int>::ok(pos);
}


}  // namespace HttpMessageParser
