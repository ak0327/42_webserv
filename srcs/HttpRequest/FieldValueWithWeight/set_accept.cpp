#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"

namespace {

Result<MediaType *, int> parse_valid_media_range(const std::string &field_value,
												 std::size_t start_pos,
												 std::size_t *end_pos) {
	std::size_t pos, end;
	MediaType *media_type;
	std::string type, subtype;
	std::map<std::string, std::string> parameters;
	Result<int, int> result;

	if (!end_pos) {
		return Result<MediaType *, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty()) {
		return Result<MediaType *, int>::err(ERR);
	}
	pos = start_pos;
	result = HttpMessageParser::parse_madia_type(field_value, pos, &end,
												 &type, &subtype, &parameters);
	if (result.is_err()) {
		return Result<MediaType *, int>::err(ERR);
	}
	*end_pos = end;

	try {
		media_type = new MediaType(type, subtype, parameters);
		if (media_type->is_err()) {
			delete media_type;
			return Result<MediaType *, int>::err(ERR);
		}
		return Result<MediaType *, int>::ok(media_type);
	} catch (const std::bad_alloc &e) {
		return Result<MediaType *, int>::err(STATUS_SERVER_ERROR);
	}
}

Result<std::set<FieldValueWithWeight>, int>
parse_and_validate_media_range_with_weight_set(const std::string &field_value) {
	std::set<FieldValueWithWeight> media_range_weight_set;
	FieldValueWithWeight media_range_with_weight;
	std::size_t pos, end;
	MediaType *media_range;
	double weight;
	Result<MediaType *, int> media_range_result;
	Result<double, int> weight_result;
	Result<std::size_t, int> skip_result;


	if (field_value.empty()) {
		return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
	}
	pos = 0;
	while (field_value[pos]) {
		media_range_result = parse_valid_media_range(field_value, pos, &end);
		if (media_range_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		media_range = media_range_result.ok_value();
		pos = end;

		HttpMessageParser::skip_ows(field_value, &pos);

		weight_result = FieldValueWithWeight::parse_valid_weight(field_value, pos, &end);
		if (weight_result.is_err()) {
			delete media_range;
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		weight = weight_result.ok_value();
		pos = end;

		media_range_with_weight = FieldValueWithWeight(media_range, weight);
		media_range_weight_set.insert(media_range_with_weight);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<FieldValueWithWeight>, int>::err(ERR);
		}
		pos = skip_result.ok_value();
	}
	return Result<std::set<FieldValueWithWeight>, int>::ok(media_range_weight_set);
}


}  // namespace

//  Accept = #( media-range [ weight ] )
//  media-range    = ( "*/*"
//                     / ( type "/" "*" )
//                     / ( type "/" subtype )
//                    ) parameters
// https://www.rfc-editor.org/rfc/rfc9110#field.accept
//
// type = token
// subtype = token
// parameters = *( OWS ";" OWS [ parameter ] )
// parameter = parameter-name "=" parameter-value
// parameter-name = token
// parameter-value = ( token / quoted-string )
//
// weight = OWS ";" OWS "q=" qvalue
// qvalue = ( "0" [ "." 0*3DIGIT ] )
//        / ( "1" [ "." 0*3("0") ] )

// std::set<FieldValueWithSet>
// FieldValueWithSet : MediaType, weight
Result<int, int> HttpRequest::set_accept(const std::string &field_name,
										 const std::string &field_value) {
	Result<std::set<FieldValueWithWeight>, int> result;
	std::set<FieldValueWithWeight> media_range_weight_set;

	clear_field_values_of(field_name);

    try {
        result = parse_and_validate_media_range_with_weight_set(field_value);
        if (result.is_err()) {
            if (result.err_value() == STATUS_SERVER_ERROR) {
                return Result<int, int>::err(STATUS_SERVER_ERROR);
            }
            return Result<int, int>::ok(OK);
        }

        media_range_weight_set = result.ok_value();
        this->request_header_fields_[field_name] = new FieldValueWithWeightSet(media_range_weight_set);
        return Result<int, int>::ok(OK);
    } catch (const std::bad_alloc &e) {
        return Result<int, int>::ok(STATUS_SERVER_ERROR);
    }
}
