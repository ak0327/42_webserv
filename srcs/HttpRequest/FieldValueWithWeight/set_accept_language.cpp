#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"

namespace {

/*
 language-range  = (1*8ALPHA *("-" 1*8alphanum)) / "*"
 alphanum        = ALPHA / DIGIT
 */

void skip_langage_range(const std::string &field_value,
						std::size_t start_pos,
						std::size_t *end_pos) {
	std::size_t pos, len, tmp_pos;
	std::string content_coding;
	const std::size_t alnum_min = 1;
	const std::size_t alnum_max = 8;
	const std::size_t alpha_min = 1;
	const std::size_t alpha_max = 8;

	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return;
	}
	pos = start_pos;
	if (field_value[pos] == '*') {
		*end_pos = pos + 1;
		return;
	}

	len = 0;
	while (field_value[pos + len] && std::isalpha(field_value[pos + len])) {
		++len;
	}
	if (len < alnum_min || alnum_max < len) {
		return;
	}
	pos += len;

	while (field_value[pos]) {
		if (field_value[pos] != '-') {
			break;
		}
		tmp_pos = pos + 1;

		len = 0;
		while (field_value[tmp_pos + len] && std::isalnum(field_value[tmp_pos + len])) {
			++len;
		}
		if (len < alpha_min || alpha_max < len) {
			break;
		}
		pos = tmp_pos + len;
	}
	*end_pos = pos;
}

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
	skip_langage_range(field_value, pos, &end);
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

Result<SingleFieldValue *, int> parse_valid_language_range(const std::string &field_value,
														   std::size_t start_pos,
														   std::size_t *end_pos) {
	std::size_t pos, end;
	SingleFieldValue *single_field_value;
	std::string language_range;
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
	language_range = result.ok_value();
	*end_pos = end;

	try {
		single_field_value = new SingleFieldValue(language_range);
		return Result<SingleFieldValue *, int>::ok(single_field_value);
	} catch (const std::bad_alloc &e) {
		return Result<SingleFieldValue *, int>::err(STATUS_SERVER_ERROR);
	}
}


Result<std::set<FieldValueWithWeight>, int>
parse_and_validate_language_range_with_weight_set(const std::string &field_value) {
	std::set<FieldValueWithWeight> language_range_set;
	FieldValueWithWeight language_range_with_weight;
	SingleFieldValue *language_range;
	double weight;
	std::size_t pos, end;
	Result<SingleFieldValue *, int> language_range_result;
	Result<double, int> weight_result;
	Result<std::size_t, int> skip_result;

	if (field_value.empty()) {
		return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
	}
	pos = 0;
	while (field_value[pos]) {
		language_range_result = parse_valid_language_range(field_value, pos, &end);
		if (language_range_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		language_range = language_range_result.ok_value();
		pos = end;

		HttpMessageParser::skip_ows(field_value, &pos);

		weight_result = FieldValueWithWeight::parse_valid_weight(field_value, pos, &end);
		if (weight_result.is_err()) {
			delete language_range;
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		weight = weight_result.ok_value();
		pos = end;

		language_range_with_weight = FieldValueWithWeight(language_range, weight);
		language_range_set.insert(language_range_with_weight);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		pos = skip_result.ok_value();
	}
	return Result<std::set<FieldValueWithWeight>, int>::ok(language_range_set);
}


}  // namespace

// todo: Accept-Language
/*
 Accept-Language = #( language-range [ weight ] )
 language-range  = (1*8ALPHA *("-" 1*8alphanum)) / "*"
 alphanum        = ALPHA / DIGIT
 https://datatracker.ietf.org/doc/html/rfc4647#section-2.1
 */
// std::set<FieldValueWithSet>
// FieldValueWithSet : SingleFieldValue, weight
Result<int, int> HttpRequest::set_accept_language(const std::string &field_name,
												  const std::string &field_value) {
	Result<std::set<FieldValueWithWeight>, int> result;
	std::set<FieldValueWithWeight> language_range_weight_set;

	clear_field_values_of(field_name);

    try {
        result = parse_and_validate_language_range_with_weight_set(field_value);
        if (result.is_err()) {
            if (result.err_value() == STATUS_SERVER_ERROR) {
                return Result<int, int>::err(STATUS_SERVER_ERROR);
            }
            return Result<int, int>::ok(OK);
        }

        language_range_weight_set = result.ok_value();
        this->request_header_fields_[field_name] = new FieldValueWithWeightSet(language_range_weight_set);
        return Result<int, int>::ok(OK);
    } catch (const std::bad_alloc &e) {
        return Result<int, int>::ok(STATUS_SERVER_ERROR);
    }
}
