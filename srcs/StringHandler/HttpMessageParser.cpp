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

std::size_t count(const std::vector<std::string> &vec, const std::string &target) {
	return std::count(vec.begin(), vec.end(), target);
}

// Zeller's congruence
std::string calculate_day_name(int year, int month, int day) {
	if (month < 3) {
		month += 12;
		year -= 1;
	}
	int c = year / 100;
	int y = year % 100;
	int h = (day + 13 * (month + 1) / 5 + y + y / 4 + 5 * c + c / 4) % 7;

	std::vector<std::string> day_names;
	day_names.push_back(std::string(SAT));
	day_names.push_back(std::string(SUN));
	day_names.push_back(std::string(MON));
	day_names.push_back(std::string(TUE));
	day_names.push_back(std::string(WED));
	day_names.push_back(std::string(THU));
	day_names.push_back(std::string(FRI));

	if (h < 0 || static_cast<int>(day_names.size()) <= h) {
		return std::string(EMPTY);
	}
	return day_names[h];
}

/*
  day-name     = %s"Mon" / %s"Tue" / %s"Wed"
               / %s"Thu" / %s"Fri" / %s"Sat" / %s"Sun"

  date1        = day SP month SP year
               ; e.g., 02 Jun 1982

  day          = 2DIGIT
  month        = %s"Jan" / %s"Feb" / %s"Mar" / %s"Apr"
               / %s"May" / %s"Jun" / %s"Jul" / %s"Aug"
               / %s"Sep" / %s"Oct" / %s"Nov" / %s"Dec"
  year         = 4DIGIT
 */
Result<int, int> parse_date1(const std::string &http_date,
							 std::string *day,
							 std::string *month,
							 std::string *year,
							 std::size_t start_pos,
							 std::size_t *end_pos) {
	Result<std::string, int> day_result, month_result, year_result;
	std::size_t pos, end;

	if (!day || !month || !year || !end_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	day_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (day_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*day = day_result.get_ok_value();
	pos = end;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	month_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (month_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*month = month_result.get_ok_value();
	pos = end;

	if (http_date[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	year_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (year_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*year = year_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
  time-of-day  = hour ":" minute ":" second
               ; 00:00:00 - 23:59:60 (leap second)

  hour         = 2DIGIT
  minute       = 2DIGIT
  second       = 2DIGIT
 */
Result<int, int> parse_time_of_day(const std::string &http_date,
								   std::string *hour,
								   std::string *minute,
								   std::string *second,
								   std::size_t start_pos,
								   std::size_t *end_pos) {
	Result<std::string, int> hour_result, minute_result, second_result;
	std::size_t pos, end;

	if (!hour || !minute || !second || !end_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	hour_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end);
	if (hour_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*hour = hour_result.get_ok_value();
	pos = end;

	if (http_date[pos] != COLON) { return Result<int, int>::err(ERR); }
	pos++;

	minute_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COLON, &end);
	if (minute_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*minute = minute_result.get_ok_value();
	pos = end;

	if (http_date[pos] != COLON) { return Result<int, int>::err(ERR); }
	pos++;

	second_result = StringHandler::parse_pos_to_delimiter(http_date, pos, SP, &end);
	if (second_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*second = second_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
 IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT
  ; fixed length/zone/capitalization subset of the format
  ; see Section 3.3 of [RFC5322]

  IMF-fixdate  = day-name "," SP date1 SP time-of-day SP GMT

 GMT          = %s"GMT"
 */
Result<int, int> parse_imf_fixdate(const std::string &http_date,
								   std::string *day_name,
								   std::string *day,
								   std::string *month,
								   std::string *year,
								   std::string *hour,
								   std::string *minute,
								   std::string *second,
								   std::string *gmt) {
	std::size_t pos, end_pos;
	Result<std::string, int> day_name_result, gmt_result;
	Result<int, int> day1_result, time_of_day_result;


	if (!day_name || !day || !month || !year || !hour || !minute || !second || !gmt) {
		return Result<int, int>::err(ERR);
	}

	pos = 0;
	day_name_result = StringHandler::parse_pos_to_delimiter(http_date, pos, COMMA, &end_pos);
	if (day_name_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*day_name = day_name_result.get_ok_value();
	pos = end_pos;

	if (http_date[pos] != COMMA) { return Result<int, int>::err(ERR); }
	pos++;

	if (http_date[pos] != SP) { return Result<int, int>::err(ERR); }
	pos++;

	day1_result = parse_date1(http_date, day, month, year, pos, &end_pos);
	if (day1_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	pos = end_pos;

	if (http_date[pos] != SP) { return Result<int, int>::err(ERR); }
	pos++;

	time_of_day_result = parse_time_of_day(http_date, hour, minute, second, pos, &end_pos);
	if (time_of_day_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	pos = end_pos;

	// SP
	if (http_date[pos] != SP) { return Result<int, int>::err(ERR); }
	pos++;

	// GMT
	gmt_result = StringHandler::parse_pos_to_delimiter(http_date, pos, '\0', NULL);
	if (gmt_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*gmt = gmt_result.get_ok_value();

	return Result<int, int>::ok(OK);
}

Result <int, int> validate_imf_fixdate(const std::string &day_name,
									   const std::string &day,
									   const std::string &month,
									   const std::string &year,
									   const std::string &hour,
									   const std::string &minute,
									   const std::string &second,
									   const std::string &gmt) {
	int day_num, month_num, year_num, hour_num, minute_num, second_num;
	std::vector<std::string>::const_iterator month_itr;
	bool succeed;

	// day1
	day_num = HttpMessageParser::to_integer_num(day, &succeed);
	if (day.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	month_itr = std::find(MONTHS.begin(), MONTHS.end(), month);
	if (month_itr == MONTHS.end()) {
		return Result<int, int>::err(ERR);
	}
	month_num = static_cast<int>(std::distance(MONTHS.begin(), month_itr)) + 1;

	year_num = HttpMessageParser::to_integer_num(year, &succeed);
	if (year.length() != 4 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	if (!HttpMessageParser::is_valid_day1(year_num, month_num, day_num)) {
		return Result<int, int>::err(ERR);
	}

	// time-of-date
	hour_num = HttpMessageParser::to_integer_num(hour, &succeed);
	if (hour.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	minute_num = HttpMessageParser::to_integer_num(minute, &succeed);
	if (minute.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	second_num = HttpMessageParser::to_integer_num(second, &succeed);
	if (second.length() != 2 || !succeed) {
		return Result<int, int>::err(ERR);
	}

	if (!HttpMessageParser::is_valid_time_of_day(hour_num, minute_num, second_num)) {
		return Result<int, int>::err(ERR);
	}

	// day_name
	if (std::find(DAY_NAMES.begin(), DAY_NAMES.end(), day_name) == DAY_NAMES.end()) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_day_name(day_name, year_num, month_num, day_num)) {
		return Result<int, int>::err(ERR);
	}

	// gmt
	if (gmt != std::string(GMT)) {
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
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
	if (!is_vchar(c)) {
		return false;
	}
	if (is_delimiters(c)) {
		return false;
	}
	return true;
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
	// todo
	return HttpMessageParser::is_token(str);
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

bool is_quoted_pair(const std::string &str, std::size_t pos) {
	if (str[pos] != '\\') { return false; }

	return (str[pos] == HT
			|| str[pos] == SP
			|| is_vchar(str[pos])
			|| is_obs_text(str[pos]));
}

/*
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )

 quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 */
void skip_transfer_parameter(const std::string &str,
							 std::size_t *pos,
							 bool *succeed) {
	if (!succeed) { return; }

	*succeed = false;

	// token
	if (!is_tchar(str[*pos])) { return; }
	while (is_tchar(str[*pos])) { *pos += 1; }

	// BWS
	skip_ows(str, &*pos);

	// '='
	if (str[*pos] != '=') { return; }
	*pos += 1;

	// BWS
	skip_ows(str, &*pos);

	if (is_tchar(str[*pos])) {
		// token
		while (str[*pos] && is_tchar(str[*pos])) {
			*pos += 1;
		}
	} else if (str[*pos] == '\"') {
		// quoted-string
		*pos += 1;
		while (str[*pos]) {
			if (is_qdtext(str[*pos])) {
				*pos += 1;
			} else if (is_quoted_pair(str, *pos)) {
				*pos += 2;
			} else {
				return;
			}  // error
			if (str[*pos] == '\"') {
				*pos += 1;
			}
		}
	} else { return; }  // error
	*succeed = true;
}

/*
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )

  Transfer-Encoding
  = [ transfer-coding *( OWS "," OWS transfer-coding ) ]
  = [ token *( OWS ";" OWS transfer-parameter ) *( OWS "," OWS token *( OWS ";" OWS transfer-parameter ) )
 */
bool is_transfer_coding(const std::string &str) {
	std::size_t pos;
	bool		succeed;

	if (str.empty()) {
		return false;
	}

	pos = 0;
	// token
	while (is_tchar(str[pos])) { pos++; }

	if (str[pos] == '\0') {
		return true;
	}

	// *( OWS ";" OWS transfer-parameter )
	while (str[pos]) {
		skip_ows(str, &pos);
		if (str[pos] != SEMICOLON) {
			return false;
		}
		pos++;

		skip_ows(str, &pos);
		if (str[pos] == '\0') {
			return false;
		}

		skip_transfer_parameter(str, &pos, &succeed);
		if (!succeed) {
			return false;
		}
	}
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

bool is_trailer_allowed_field_name(const std::string &field_name) {
	if (count(MESSAGE_FRAMING_HEADERS, field_name) != 0) {
		return false;
	}
	if (count(ROUTING_HEADERS, field_name) != 0) {
		return false;
	}
	if (count(REQUEST_MODIFIERS, field_name) != 0) {
		return false;
	}
	if (count(AUTHENTICATION_HEADERS, field_name) != 0) {
		return false;
	}
	if (field_name == CONTENT_ENCODING
		|| field_name == CONTENT_TYPE
		|| field_name == CONTENT_RANGE
		|| field_name == TRAILER) {
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
// todo
bool is_absolute_uri(const std::string &field_value) {
	(void)field_value;
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
// todo
bool is_partial_uri(const std::string &field_value) {
	(void)field_value;
	return true;
}

std::string parse_uri_host(const std::string &str,
						   std::size_t start_pos,
						   std::size_t *end_pos) {
	(void)str;
	(void)start_pos;
	(void)end_pos;
	return "";
}

std::string parse_port(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	(void)str;
	(void)start_pos;
	(void)end_pos;
	return "";
}

/*
 Date = HTTP-date

 HTTP-date    = IMF-fixdate / obs-date

 obs-date     = rfc850-date / asctime-date
  rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT

  day-name-l   = %s"Monday" / %s"Tuesday" / %s"Wednesday"
               / %s"Thursday" / %s"Friday" / %s"Saturday"
               / %s"Sunday"

  date2        = day "-" month "-" 2DIGIT
               ; e.g., 02-Jun-82

  asctime-date = day-name SP date3 SP time-of-day SP year
  date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
               ; e.g., Jun  2

 https://www.rfc-editor.org/rfc/rfc9110#field.date
 */
Result<date_format, int> parse_http_date(const std::string &http_date,
										 std::string *day_name,
										 std::string *day,
										 std::string *month,
										 std::string *year,
										 std::string *hour,
										 std::string *minute,
										 std::string *second,
										 std::string *gmt) {
	Result<int, int> imf_fixdate_result;
	// Result<int, int> rfc850_date_result, asctime_date_result;  // todo

	imf_fixdate_result = parse_imf_fixdate(http_date,
										   day_name,
										   day, month, year,
										   hour, minute, second,
										   gmt);
	if (imf_fixdate_result.is_ok()) {
		return Result<date_format, int>::ok(IMF_FIXDATE);
	}

	// todo: parse_rfc850_date()
	// todo: parse_asctime_date()

	return Result<date_format, int>::err(ERR);
}

bool is_leap_year(int year) {
	if (year % 4 != 0) {
		return false;
	}
	if (year % 100 == 0 && year % 400 != 0) {
		return false;
	}
	return true;
}

bool is_valid_day1(int year, int month, int day) {
	int month_idx;
	int days_in_month[12];
	const int jan_idx = 0, feb_idx = 1, mar_idx = 2, apr_idx = 3,
			  may_idx = 4, jun_idx = 5, jul_idx = 6, aug_idx = 7,
			  sep_idx = 8, oct_idx = 9, nov_idx = 10, dec_idx = 11;

	if (year < GREGORIAN_CALENDAR || month < 1 || 12 < month) {
		return false;
	}
	month_idx = month - 1;

	days_in_month[jan_idx] = 31;
	days_in_month[feb_idx] = is_leap_year(year) ? 29 : 28;
	days_in_month[mar_idx] = 31;
	days_in_month[apr_idx] = 30;
	days_in_month[may_idx] = 31;
	days_in_month[jun_idx] = 30;
	days_in_month[jul_idx] = 31;
	days_in_month[aug_idx] = 31;
	days_in_month[sep_idx] = 30;
	days_in_month[oct_idx] = 31;
	days_in_month[nov_idx] = 30;
	days_in_month[dec_idx] = 31;

	return 1 <= day && day <= days_in_month[month_idx];
}

bool is_valid_time_of_day(int hour, int minute, int second) {
	if (hour < 0 || 23 < hour) {
		return false;
	}
	if (minute < 0 || 59 <minute) {
		return false;
	}
	if (second < 0 || 59 < second) {
		return false;
	}
	return true;
}

bool is_valid_day_name(const std::string &day_name, int year, int month, int day) {
	std::string zellers_day_name = calculate_day_name(year, month, day);

	return day_name == zellers_day_name;
}

Result<int, int> validate_http_date(date_format format,
									const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt) {
	Result<int, int> validate_result;

	if (format == IMF_FIXDATE) {
		validate_result = validate_imf_fixdate(day_name,
											   day, month, year,
											   hour, minute, second,
											   gmt);
	}
	// else if (format == RFC850_DATE) {
	// 	// todo
	// } else {
	// 	// todo
	// }

	if (validate_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}


}  // namespace HttpMessageParser
