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

// todo: test
std::string obtain_word_before_delimiter(const std::string &field_value,
										 const char &delimiter)
{
	return field_value.substr(0, field_value.find(delimiter));
}

// todo: test
std::string obtain_word_after_delimiter(const std::string &str, char delimiter)
{
	return str.substr(str.find(delimiter) + 1);
}

// todo: test
std::string	obtain_weight(const std::string &field_value)
{
	return (obtain_word_after_delimiter(field_value, '='));
}

// todo: test
std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (is_whitespace(field_value_with_ows[before_pos]) == true
			&& before_pos != field_value_with_ows.length())
		++before_pos;
	while (is_whitespace(field_value_with_ows[after_pos]) == true
			&& after_pos != 0)
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

// todo: test
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

	precision_num = get_fractional_part(&str[idx],
										&precision_idx);
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

/*
 extlang       = 3ALPHA              ; selected ISO 639 codes
                 *2("-" 3ALPHA)      ; permanently reserved
 */
void skip_extlang(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos) {
	std::size_t pos, tmp_pos, len, cnt;


	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (len != 3) { return; }
	pos += len;

	cnt = 0;
	while (str[pos]) {
		if (str[pos] != '-') { break; }  // Followed by a non-extlang string

		len = 0;
		tmp_pos = pos + 1;
		while (str[tmp_pos + len] && std::isalpha(str[tmp_pos + len])) {
			++len;
		}
		if (len != 3) {
			break;
		}
		pos = tmp_pos + len;
		++cnt;
		if (cnt == 2) {
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

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (2 <= len && len <= 3) {
		pos += len;
		if (str[pos] == '-') {
			skip_extlang(str, pos + 1, &end);
			if (pos + 1 != end) {
				pos = end;
			}
		}
	} else if (len == 4 || (5 <= len && len <= 8)) {
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

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	while (str[pos + len] && std::isalpha(str[pos + len])) {
		++len;
	}
	if (len != 4) { return; }
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

	if (!end_pos) { return; }
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	pos = start_pos;
	len = 0;
	if (std::isalpha(str[pos])) {
		while (str[pos + len] && std::isalpha(str[pos + len])) {
			++len;
		}
		if (len != 2) { return; }
		pos += len;
	} else if (std::isdigit(str[pos])) {
		while (str[pos + len] && std::isdigit(str[pos + len])) {
			++len;
		}
		if (len != 3) { return; }
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

	if (5 <= len1 && len1 <= 8) {
		pos += len1;
	} else if (len2 == 3) {
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
		if (len < 2 || 8 < len) { break; }
		pos = tmp_pos + len;
		++cnt;
	}

	if (cnt == 0) {
		return;
	}
	*end_pos = pos;
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
		if (len < 1 || 8 < len) {
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

/*
 grandfathered = irregular           ; non-redundant tags registered
               / regular             ; during the RFC 3066 era
 https://tex2e.github.io/rfc-translater/html/rfc5646.html
 */
// todo: test

// todo: 文字列の一致をどこまで判定するか？区切り文字の決め方がわからない
//    regular = "zh-xiang"
//    str     = "zh-xiangxxx"
//                       ^ end_pos? NG?
//              "zh-xiang-xxx"
//              "zh-xiang;xxx"
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

/*
 etagc = "!" / %x23-7E ; '#'-'~' / obs-text
 */
bool is_etag(char c) {
	return (c == '!' || ('#' <= c && c <= '~') || is_obs_text(c));
}

/*
 // opaque-tag = DQUOTE *etagc DQUOTE
 */
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

void skip_ows(const std::string &str, std::size_t *pos) {
	if (!pos) { return; }
	if (str.empty() || str.length() < *pos) {
		return;
	}

	while (is_whitespace(str[*pos])) {
		*pos += 1;
	}
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
bool is_pct_encoded(const std::string &str, std::size_t pos) {
	if (str.empty() || str.length() < pos) {
		return false;
	}

	return (str[pos] == '%'
			&& is_hexdig(str[pos + 1])
			&& is_hexdig(str[pos + 2]));
}

// todo: test
bool is_http_date(const std::string &str) {
	Date date = Date(str);
	return date.is_ok();
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
 absolute-URI  = scheme ":" hier-part [ "?" query ]

 hier-part     = "//" authority path-abempty
              / path-absolute
              / path-rootless
              / path-empty

 scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 path-rootless = segment-nz *( "/" segment )

 https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
 */
// todo: test
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
// todo: test
bool is_partial_uri(const std::string &str) {
	(void)str;
	// todo
	return true;
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
 comment        = "(" *( ctext / quoted-pair / comment ) ")"
 ctext          = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
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
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	len = 0;
	while (str[pos + len] && is_hexdig(str[pos + len])) {
		++len;
		if (len == 4) {
			break;
		}
	}
	if (len == 0) {
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

// if double colon not found, returns error
Result<std::size_t, int> get_double_colon_pos(const std::string &str,
											  std::size_t start_pos) {
	std::size_t pos;

	if (str.empty() || str.length() < start_pos) {
		return Result<std::size_t, int>::err(ERR);
	}
	pos = start_pos;
	while (str[pos] && str[pos + 1]) {
		if (str[pos] == ':' && str[pos + 1] == ':') {
			return Result<std::size_t, int>::ok(pos);
		}
		++pos;
	}
	return Result<std::size_t, int>::err(ERR);
}

bool is_ipv6address(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipv6address(str, 0, &end);
	return str[end] == '\0';
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

// IPvFuture   = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
bool is_ipvfuture(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipvfuture(str, 0, &end);
	return str[end] == '\0';
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
bool is_ip_literal(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ip_literal(str, 0, &end);
	return str[end] == '\0';
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

bool is_dec_octet(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_dec_octet(str, 0, &end);
	return str[end] == '\0';
}

/*
 dec-octet   = DIGIT                 ; 0-9
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
	std::size_t pos, end, dec_octet_cnt;
	if (!end_pos) { return; }

	pos = start_pos;
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) { return; }

	dec_octet_cnt = 0;
	while (str[pos] && dec_octet_cnt < 4) {
		skip_dec_octet(str, pos, &end);
		if (pos == end) { return; }
		pos = end;
		++dec_octet_cnt;
		if (dec_octet_cnt < 4) {
			if (str[pos] != '.') { return; }
			++pos;
		}
	}
	if (dec_octet_cnt != 4) { return; }
	*end_pos = pos;
}

bool is_ipv4address(const std::string &str) {
	std::size_t end;

	if (str.empty()) {
		return false;
	}
	skip_ipv4address(str, 0, &end);
	return str[end] == '\0';
}

// unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
bool is_unreserved(char c) {
	return (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~');
}

// sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
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

// reg-name    = *( unreserved / pct-encoded / sub-delims )
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

bool is_valid_uri_host(const std::string &uri_host) {
	return (HttpMessageParser::is_ip_literal(uri_host)
			|| HttpMessageParser::is_ipv4address(uri_host)
			|| HttpMessageParser::is_reg_name(uri_host));
}

bool is_valid_port(const std::string &port) {
	int port_num;
	bool succeed;

	port_num = HttpMessageParser::to_integer_num(port, &succeed);
	return (succeed && (PORT_MIN <= port_num && port_num <= PORT_MAX));
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
Result<std::string, int> parse_uri_host(const std::string &field_value,
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
Result<std::string, int> parse_port(const std::string &field_value,
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

}  // namespace HttpMessageParser
