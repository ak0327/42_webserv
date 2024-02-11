#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "MapSetFieldValues.hpp"

namespace {


Result<std::string, int> parse_received_by(const std::string &field_value,
										   std::size_t start_pos,
										   std::size_t *end_pos) {
	std::size_t len;
	std::string received_by;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	len = 0;
	while (field_value[start_pos + len]
		   && !HttpMessageParser::is_whitespace(field_value[start_pos + len])
		   && field_value[start_pos + len] != COMMA) {
		++len;
	}
	if (len == 0) {
		return Result<std::string, int>::err(ERR);
	}
	received_by = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(received_by);
}

Result<std::string, int> parse_comment(const std::string &field_value,
									   std::size_t start_pos,
									   std::size_t *end_pos) {
	std::size_t pos, len, end;
	std::string comment;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	if (!HttpMessageParser::is_whitespace(field_value[start_pos])) {
		return Result<std::string, int>::ok(std::string(EMPTY));
	}
	pos = start_pos;
	if (field_value[pos + 1] == '(') {
		++pos;
		len = 0;
		HttpMessageParser::skip_comment(field_value, pos, &end);
		if (pos == end) {
			return Result<std::string, int>::err(ERR);
		}
		len = end - pos;
		comment = field_value.substr(pos, len);
		pos += len;
	}
	*end_pos = pos;
	return Result<std::string, int>::ok(comment);
}

/*
 Via = #( received-protocol RWS received-by [ RWS comment ] )
 1#element => element *( OWS "," OWS element )

 received-protocol = [ protocol-name "/" ] protocol-version
 protocol-name     = token
 protocol-version  = token
 received-by       = pseudonym [ ":" port ]
 pseudonym         = token
 https://www.rfc-editor.org/rfc/rfc9110#field.via

 RWS = 1*( SP / HTAB )
 */
Result<int, int> parse_via_elems(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos,
								 std::string *received_protocol,
								 std::string *received_by,
								 std::string *comment) {
	std::size_t pos, end;
	Result<std::string, int> protocol_result, received_by_result, comment_result;

	if (!end_pos || !received_protocol || !received_by || !comment) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}

	// received-protocol
	protocol_result = StringHandler::parse_pos_to_wsp(field_value, pos, &end);
	if (protocol_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*received_protocol = protocol_result.get_ok_value();
	pos = end;

	// RWS
	if (!HttpMessageParser::is_whitespace(field_value[pos])) {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// received-by
	received_by_result = parse_received_by(field_value, pos, &end);
	if (received_by_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*received_by = received_by_result.get_ok_value();
	pos = end;

	// [ RWS comment ]
	comment_result = parse_comment(field_value, pos, &end);
	if (comment_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*comment = comment_result.get_ok_value();
	pos = end;

	*end_pos = pos;
	return Result<int, int>::ok(OK);
}

/*
 received-protocol = [ protocol-name "/" ] protocol-version
 protocol-name     = token
 protocol-version  = token
 */
bool is_valid_received_protocol(const std::string &received_protocol) {
	std::string protocol_name, protocol_version;
	std::size_t pos;

	if (received_protocol.empty()) {
		return false;
	}
	pos = received_protocol.find(SLASH);
	if (pos == std::string::npos) {
		protocol_version = received_protocol;
		return HttpMessageParser::is_token(protocol_version);
	} else {
		protocol_name = received_protocol.substr(0, pos);
		++pos;
		protocol_version = received_protocol.substr(pos);
		return (HttpMessageParser::is_token(protocol_name)
				&& HttpMessageParser::is_token(protocol_version));
	}
}

/*
 received-by       = pseudonym [ ":" port ]
 pseudonym         = token
 */
bool is_valid_received_by(const std::string &received_by) {
	std::string pseudonym, port;
	std::size_t pos;

	pos = received_by.find(COLON);
	if (pos == std::string::npos) {
		pseudonym = received_by;
		return HttpMessageParser::is_token(pseudonym);
	} else {
		pseudonym = received_by.substr(0, pos);
		++pos;
		port = received_by.substr(pos);
		return (HttpMessageParser::is_token(pseudonym)
				&& HttpMessageParser::is_port(port));
	}
}

bool is_valid_comment(const std::string &comment) {
	std::size_t end;

	if (comment.empty()) {
		return true;
	}
	HttpMessageParser::skip_comment(comment, 0, &end);
	return comment[end] == '\0';
}

Result<int, int> validate_via_elems(const std::string &received_protocol,
									const std::string &received_by,
									const std::string &comment) {
	if (!is_valid_received_protocol(received_protocol)) {
		return Result<int, int>::err(ERR);
	}
	if (!is_valid_received_by(received_by)) {
		return Result<int, int>::err(ERR);
	}
	if (!is_valid_comment(comment)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

// Via = #( received-protocol RWS received-by [ RWS comment ] )
Result<std::map<std::string, std::string>, int>
parse_and_validate_via_elems(const std::string &field_value,
							 std::size_t start_pos,
							 std::size_t *end_pos) {
	std::string received_protocol, received_by, comment;
	std::map<std::string, std::string> via_elems;
	Result<int, int> parse_result, validate_result;

	parse_result = parse_via_elems(field_value,
								   start_pos, end_pos,
								   &received_protocol,
								   &received_by,
								   &comment);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	validate_result = validate_via_elems(received_protocol, received_by, comment);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	via_elems[std::string(RECEIVED_PROTOCOL)] = received_protocol;
	via_elems[std::string(RECEIVED_BY)] = received_by;
	via_elems[std::string(COMMENT)] = comment;

	return Result<std::map<std::string, std::string>, int>::ok(via_elems);
}


}  // namespace

/*
 Via = #( received-protocol RWS received-by [ RWS comment ] )

 received-protocol = [ protocol-name "/" ] protocol-version
 protocol-name     = token
 protocol-version  = token
 received-by       = pseudonym [ ":" port ]
 pseudonym         = token
 https://www.rfc-editor.org/rfc/rfc9110#field.via

 RWS = 1*( SP / HTAB )

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
/*
 std::set<std::map<std::string, std::string> > vias = {via1, via2, ... };
  via_i["received_protocol"] = received-protocol;
  via_i["received_by"] = received-by;
  via_i["comment"] = comment;
 */
Result<int, int> HttpRequest::set_via(const std::string &field_name,
									  const std::string &field_value) {
	std::set<std::map<std::string, std::string> > via;
	Result<std::set<std::map<std::string, std::string> >, int> result;

	clear_field_values_of(field_name);

	result = HttpMessageParser::parse_map_set_field_values(field_value,
														   parse_and_validate_via_elems);
	if (result.is_err()) {
		return Result<int, int>::ok(STATUS_OK);
	}
	via = result.get_ok_value();

	this->request_header_fields_[field_name] = new MapSetFieldValues(via);
	return Result<int, int>::ok(STATUS_OK);
}
