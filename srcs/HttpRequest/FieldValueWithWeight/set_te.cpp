#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "ValueAndMapFieldValues.hpp"

namespace {


Result<std::string, int> parse_token(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos) {
	std::size_t pos, end, len;
	std::string token;

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
	token = field_value.substr(pos, len);

	*end_pos = end;
	return Result<std::string, int>::ok(token);
}

// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
Result<int, int>
validate_transfer_parameter(const std::map<std::string, std::string> &disposition_param) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;

	if (disposition_param.empty()) {
		return Result<int, int>::ok(OK);
	}

	for (itr = disposition_param.begin(); itr != disposition_param.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (HttpMessageParser::is_token(key)
			&& (HttpMessageParser::is_token(value)
				|| HttpMessageParser::is_quoted_string(value))) {
			continue;
		}
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<std::map<std::string, std::string>, int>
parse_and_validate_transfer_parameter(const std::string &field_value,
									  std::size_t start_pos,
									  std::size_t *end_pos) {
	std::map<std::string, std::string> transfer_parameter;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	parse_result = HttpMessageParser::parse_parameters(field_value,
													   start_pos, end_pos,
													   HttpMessageParser::skip_token,
													   HttpMessageParser::skip_token_or_quoted_string,
													   true);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}
	transfer_parameter = parse_result.ok_value();

	validate_result = validate_transfer_parameter(transfer_parameter);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string> , int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(transfer_parameter);
}

/*
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )
 */
Result<ValueAndMapFieldValues *, int> parse_valid_transfer_coding(const std::string &field_value,
																  std::size_t start_pos,
																  std::size_t *end_pos) {
	std::size_t pos, end;
	ValueAndMapFieldValues *transfer_coding;
	std::string value;
	std::map<std::string, std::string> value_map;
	Result<int, int> result;

	if (!end_pos) {
		return Result<ValueAndMapFieldValues *, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty()) {
		return Result<ValueAndMapFieldValues *, int>::err(ERR);
	}
	pos = start_pos;
	result = HttpMessageParser::parse_value_and_map_values(field_value,
														   pos, &end,
														   &value,
														   &value_map,
														   parse_token,
														   parse_and_validate_transfer_parameter);
	if (result.is_err()) {
		return Result<ValueAndMapFieldValues *, int>::err(ERR);
	}
	*end_pos = end;

	try {
		transfer_coding = new ValueAndMapFieldValues(value, value_map);
		return Result<ValueAndMapFieldValues *, int>::ok(transfer_coding);
	} catch (const std::bad_alloc &e) {
		return Result<ValueAndMapFieldValues *, int>::err(STATUS_SERVER_ERROR);
	}
}


Result<std::set<FieldValueWithWeight>, int>
parse_and_validate_t_codings_with_weight_set(const std::string &field_value) {
	std::set<FieldValueWithWeight> t_codings_set;
	FieldValueWithWeight t_codings;
	ValueAndMapFieldValues *transfer_coding;
	double weight;
	std::size_t pos, end;
	Result<ValueAndMapFieldValues *, int> transfer_coding_result;
	Result<double, int> weight_result;
	Result<std::size_t, int> skip_result;

	if (field_value.empty()) {
		return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
	}
	pos = 0;
	while (field_value[pos]) {
		transfer_coding_result = parse_valid_transfer_coding(field_value, pos, &end);
		if (transfer_coding_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		transfer_coding = transfer_coding_result.ok_value();
		pos = end;

		HttpMessageParser::skip_ows(field_value, &pos);

		weight_result = FieldValueWithWeight::parse_valid_weight(field_value, pos, &end);
		if (weight_result.is_err()) {
			delete transfer_coding;
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		weight = weight_result.ok_value();

		pos = end;

		t_codings = FieldValueWithWeight(transfer_coding, weight);
		t_codings_set.insert(t_codings);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		pos = skip_result.ok_value();
	}
	return Result<std::set<FieldValueWithWeight>, int>::ok(t_codings_set);
}


}  // namespace

/*
 TE                 = #t-codings
 t-codings          = "trailers" / ( transfer-coding [ weight ] )
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )
 https://www.rfc-editor.org/rfc/rfc9110#field.te
 */
// std::set<FieldValueWithSet>
// FieldValueWithSet : ValueAndMapFieldValues, weight
// FieldValueWithSet : ValueAndMapFieldValues, weight
Result<int, int> HttpRequest::set_te(const std::string &field_name,
									 const std::string &field_value) {
	Result<std::set<FieldValueWithWeight>, int> result;
	std::set<FieldValueWithWeight> t_codings_set;

	clear_field_values_of(field_name);

	result = parse_and_validate_t_codings_with_weight_set(field_value);
	if (result.is_err()) {
		if (result.err_value() == STATUS_SERVER_ERROR) {
			return Result<int, int>::err(STATUS_SERVER_ERROR);
		}
		return Result<int, int>::ok(OK);
	}

	t_codings_set = result.ok_value();
	this->request_header_fields_[field_name] = new FieldValueWithWeightSet(t_codings_set);
	return Result<int, int>::ok(OK);
}
