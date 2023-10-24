#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"
#include "SingleFieldValue.hpp"

namespace {

Result<std::string, int> parse_valid_content_coding(const std::string &field_value,
													std::size_t start_pos,
													std::size_t *end_pos) {
	std::size_t pos, end, len;
	std::string content_coding;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<std::string, int>::err(ERR);
	}
	pos = start_pos;
	HttpMessageParser::skip_token(field_value, pos, &end);
	if (pos == end) {
		return Result<std::string, int>::err(ERR);
	}
	len = end - pos;
	content_coding = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;

	if (!HttpMessageParser::is_token(content_coding)) {
		return Result<std::string, int>::err(ERR);
	}
	return Result<std::string, int>::ok(content_coding);
}

/*
 codings          = content-coding / "identity" / "*"
 content-coding   = token
 */
Result<SingleFieldValue *, int> parse_valid_codings(const std::string &field_value,
											 std::size_t start_pos,
											 std::size_t *end_pos) {
	std::size_t pos, end;
	SingleFieldValue *single_field_value;
	std::string content_coding;
	std::string type, subtype;
	std::map<std::string, std::string> parameters;
	Result<std::string, int> result;

	if (!end_pos) {
		return Result<SingleFieldValue *, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty()) {
		return Result<SingleFieldValue *, int>::err(ERR);
	}
	pos = start_pos;

	result = parse_valid_content_coding(field_value, pos, &end);
	if (result.is_err()) {
		return Result<SingleFieldValue *, int>::err(ERR);
	}
	content_coding = result.get_ok_value();
	*end_pos = end;

	try {
		single_field_value = new SingleFieldValue(content_coding);
		return Result<SingleFieldValue *, int>::ok(single_field_value);
	} catch (const std::bad_alloc &e) {
		return Result<SingleFieldValue *, int>::err(STATUS_SERVER_ERROR);
	}
}


Result<std::set<FieldValueWithWeight>, int>
parse_and_validate_coding_with_weight_set(const std::string &field_value) {
	std::set<FieldValueWithWeight> coding_weight_set;
	FieldValueWithWeight coding_with_weight;
	SingleFieldValue *codings;
	double weight;
	std::size_t pos, end;
	Result<SingleFieldValue *, int> coding_result;
	Result<double, int> weight_result;
	Result<std::size_t, int> skip_result;

	if (field_value.empty()) {
		return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
	}
	pos = 0;
	while (field_value[pos]) {
		coding_result = parse_valid_codings(field_value, pos, &end);
		if (coding_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		codings = coding_result.get_ok_value();
		pos = end;

		HttpMessageParser::skip_ows(field_value, &pos);

		if (field_value[pos] == ';') {
			++pos;
			HttpMessageParser::skip_ows(field_value, &pos);


			weight_result = FieldValueWithWeight::parse_valid_weight(field_value, pos, &end);
			if (weight_result.is_err()) {
				delete codings;
				return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
			}
			weight = weight_result.get_ok_value();
			pos = end;

		} else {
			weight = WEIGHT_INIT;
		}

		coding_with_weight = FieldValueWithWeight(codings, weight);
		coding_weight_set.insert(coding_with_weight);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		pos = skip_result.get_ok_value();
	}
	return Result<std::set<FieldValueWithWeight>, int>::ok(coding_weight_set);
}


}  // namespace

/*
 Accept-Encoding  = #( codings [ weight ] )
 codings          = content-coding / "identity" / "*"
 content-coding   = token
 https://www.rfc-editor.org/rfc/rfc9110#field.accept-encoding
 */
// std::set<FieldValueWithSet>
// FieldValueWithSet : SingleFieldValue, weight
Result<int, int> HttpRequest::set_accept_encoding(const std::string &field_name,
												  const std::string &field_value) {
	std::set<FieldValueWithWeight> codings_weight_set;
	Result<std::set<FieldValueWithWeight>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_coding_with_weight_set(field_value);
	if (result.is_err()) {
		if (result.get_err_value() == STATUS_SERVER_ERROR) {
			return Result<int, int>::err(STATUS_SERVER_ERROR);
		}
		return Result<int, int>::ok(OK);
	}

	codings_weight_set = result.get_ok_value();
	this->_request_header_fields[field_name] = new FieldValueWithWeightSet(codings_weight_set);
	return Result<int, int>::ok(OK);
}
