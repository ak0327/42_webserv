#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "ValueAndMapFieldValues.hpp"

namespace {

/*
  content-disposition = "Content-Disposition" ":"
                         disposition-type *( ";" disposition-parm )

  disposition-type    = "inline" | "attachment" | disp-ext-type
                      ; case-insensitive
  disp-ext-type       = token
 */
Result<std::string, int> parse_disposition_type(const std::string &field_value,
												std::size_t start_pos,
												std::size_t *end_pos) {
	std::string disposition_type;
	std::size_t pos, end, len;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty()) {
		return Result<std::string, int>::err(ERR);
	}

	pos = start_pos;
	end = field_value.find(';', pos);
	if (end == std::string::npos) {
		len = field_value.length();
	} else {
		len = end - pos;
	}
	disposition_type = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<std::string, int>::ok(disposition_type);
}

bool is_disposition_type(const std::string &disposition_type) {
	return (disposition_type == "inline" || disposition_type == "attachment");
}

bool is_disp_ext_type(const std::string &disp_ext_type) {
	return HttpMessageParser::is_token(disp_ext_type);
}

Result<int, int> validate_disposition_type(const std::string &disposition_type) {
	if (is_disposition_type(disposition_type)) {
		return Result<int, int>::ok(OK);
	}
	if (is_disp_ext_type(disposition_type)){
		return Result<int, int>::ok(OK);
	}
	return Result<int, int>::err(ERR);
}

Result<std::string, int> parse_and_validate_disposition_type(const std::string &field_value,
															 std::size_t start_pos,
															 std::size_t *end_pos) {
	std::string disposition_type;
	Result<std::string, int> parse_result;
	Result<int, int> validate_result;
	std::size_t pos, end;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	pos = start_pos;
	parse_result = parse_disposition_type(field_value, pos, &end);
	if (parse_result.is_err()) {
		return Result<std::string, int>::err(ERR);
	}
	disposition_type = parse_result.get_ok_value();
	*end_pos = end;

	validate_result = validate_disposition_type(disposition_type);
	if (validate_result.is_err()) {
		return Result<std::string, int>::err(ERR);
	}
	return Result<std::string, int>::ok(disposition_type);
}

Result<int, int> parse_param(const std::string &field_value,
							 std::size_t start_pos,
							 std::size_t *end_pos,
							 std::string *key,
							 std::string *value) {
	std::size_t pos, end, len;

	if (!end_pos || !key || !value) { return Result<int, int>::err(ERR); }
	*end_pos = start_pos;
	if (field_value.empty())  { return Result<int, int>::err(ERR); }
	if (field_value.length() < start_pos)  { return Result<int, int>::err(ERR); }

	// key
	pos = start_pos;
	end = field_value.find('=', pos);
	if (end == std::string::npos) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*key = field_value.substr(pos, len);

	// =
	pos += len;
	if (field_value[pos] != '=') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// value
	end = field_value.find(';', pos);
	if (end == std::string::npos) {
		end = field_value.length();
	}
	len = end - pos;
	*value = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<int, int>::ok(OK);
}

/*
  content-disposition = "Content-Disposition" ":"
                         disposition-type *( ";" disposition-parm )

  disposition-parm    = filename-parm | disp-ext-parm

  filename-parm       = "filename" "=" value
                      | "filename*" "=" ext-value

  disp-ext-parm       = token "=" value
                      | ext-token "=" ext-value
  ext-token           = <the characters in token, followed by "*">
 */
Result<std::map<std::string, std::string>, int>
parse_disposition_param(const std::string &field_value,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::map<std::string, std::string> disposition_param;
	Result<int, int> parse_result;
	std::size_t pos, end;
	std::string key, value;

	// std::cout << MAGENTA << "  &field_value[start]:[" << &field_value[start_pos] << "]" << RESET << std::endl;

	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		// std::cout << MAGENTA << "  err 1" << RESET << std::endl;
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = start_pos;
	while (field_value[pos]) {
		if (field_value[pos] != ';') {
			// std::cout << MAGENTA << "  err 2" << RESET << std::endl;
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;

		parse_result = parse_param(field_value, pos, &end, &key, &value);
		if (parse_result.is_err()) {
			// std::cout << MAGENTA << "  err 3" << RESET << std::endl;
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		disposition_param[key] = value;
		// std::cout << MAGENTA << "  key:[" << key << "], value:[" << value << "]" << RESET << std::endl;
		pos = end;
	}
	*end_pos = pos;
	return Result<std::map<std::string, std::string>, int>::ok(disposition_param);
}

bool is_param_key(const std::string &key) {
	return (key == "filename" || HttpMessageParser::is_token(key));
}

bool is_ext_param_key(const std::string &key) {
	return (key == "filename*" ||  HttpMessageParser::is_ext_token(key));
}

/*
 value         = token | quoted-string
 https://httpwg.org/specs/rfc6266.html#n-grammar
 */
bool is_param_value(const std::string &value) {
	return (HttpMessageParser::is_token(value)
			|| HttpMessageParser::is_quoted_string(value));
}

/*
 ext-value     = charset  "'" [ language ] "'" value-chars

 charset       = "UTF-8" / "ISO-8859-1" / mime-charset

 mime-charset  = 1*mime-charsetc
 mime-charsetc = ALPHA / DIGIT
			   / "!" / "#" / "$" / "%" / "&"
			   / "+" / "-" / "^" / "_" / "`"
			   / "{" / "}" / "~"
			   ; as <mime-charset> in Section 2.3 of [RFC2978]
			   ; except that the single quote is not included
			   ; SHOULD be registered in the IANA charset registry

 value-chars   = *( pct-encoded / attr-char )

 https://www.rfc-editor.org/rfc/rfc5987.html#section-3.2
 */
bool is_ext_param_value(const std::string &value) {
	std::size_t pos, end;

	if (value.empty()) { return false; }

	pos = 0;
	if (value[pos] != '\'') { return false; }
	++pos;

	HttpMessageParser::skip_language_tag(value, pos, &end);
	pos = end;

	if (value[pos] != '\'') { return false; }
	++pos;

	while (value[pos]) {
		if (HttpMessageParser::is_pct_encoded(value, pos)) {
			pos += 3;
		}
		if (HttpMessageParser::is_attr_char(value[pos])) {
			++pos;
		}
	}
	return value[pos] == '\0';
}

/*
  disposition-parm    = filename-parm | disp-ext-parm

  filename-parm       = "filename" "=" value
                      | "filename*" "=" ext-value

  disp-ext-parm       = token "=" value
                      | ext-token "=" ext-value
 */
Result<int, int>
validate_disposition_param(const std::map<std::string, std::string> &disposition_param) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;

	if (disposition_param.empty()) {
		return Result<int, int>::ok(OK);
	}

	for (itr = disposition_param.begin(); itr != disposition_param.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (is_param_key(key) && is_param_value(value)) {
			continue;
		} else if (is_ext_param_key(key) && is_ext_param_value(value)) {
			continue;
		}
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}


Result<std::map<std::string, std::string>, int>
parse_and_validate_disposition_param(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos) {
	std::map<std::string, std::string> disposition_param;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	if (!end_pos) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}

	parse_result = parse_disposition_param(field_value, start_pos, end_pos);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}
	disposition_param = parse_result.get_ok_value();

	validate_result = validate_disposition_param(disposition_param);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}
	return Result<std::map<std::string, std::string> , int>::ok(disposition_param);
}

/*
 content-disposition = "Content-Disposition" ":"
                        disposition-type *( ";" disposition-parm )

 disposition-type    = "inline" | "attachment" | disp-ext-type
                     ; case-insensitive
 disp-ext-type       = token

 disposition-parm    = filename-parm | disp-ext-parm

 filename-parm       = "filename" "=" value
                     | "filename*" "=" ext-value

 disp-ext-parm       = token "=" value
                     | ext-token "=" ext-value
 ext-token           = <the characters in token, followed by "*">
 https://httpwg.org/specs/rfc6266.html#header.field.definition
 */

Result<int, int>
parse_and_validate_content_disposition(const std::string &field_value,
									   std::string *disposition_type,
									   std::map<std::string, std::string> *disposition_param) {
	Result<int, int> result;
	std::size_t pos, end;

	pos = 0;
	result = HttpMessageParser::parse_value_and_map_values(field_value,
														   pos, &end,
														   disposition_type,
														   disposition_param,
														   parse_and_validate_disposition_type,
														   parse_and_validate_disposition_param);
	if (result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	pos = end;

	if (field_value[pos] != '\0') {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Result<int, int> HttpRequest::set_content_disposition(const std::string &field_name,
													  const std::string &field_value) {
	std::string disposition_type;
	std::map<std::string, std::string> disposition_param;
	Result<int, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_content_disposition(field_value,
													&disposition_type,
													&disposition_param);
	if (result.is_ok()) {
		this->_request_header_fields[field_name] = new ValueAndMapFieldValues(disposition_type,
																			  disposition_param);
	}
	return Result<int, int>::ok(STATUS_OK);
}
