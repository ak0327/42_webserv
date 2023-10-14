#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MediaType.hpp"

namespace {

Result<MediaType *, int> create_valid_media_type(const std::string &field_value) {
	MediaType *media_type;

	media_type =  new MediaType(field_value);
	if (media_type->is_err()) {
		delete media_type;
		return Result<MediaType *, int>::err(ERR);
	}
	return Result<MediaType *, int>::ok(media_type);
}

}  // namespace

Result<int, int> HttpRequest::set_valid_media_type(const std::string &field_name,
												   const std::string &field_value) {
	Result<MediaType *, int> date_result;
	MediaType *media_type;


	clear_field_values_of(field_name);

	date_result = create_valid_media_type(field_value);
	if (date_result.is_err()) {
		return Result<int, int>::ok(OK);
	}

	media_type = date_result.get_ok_value();
	this->_request_header_fields[field_name] = media_type;
	return Result<int, int>::ok(OK);
}

// todo: Content-Type
/*
 Content-Type = media-type
 */
Result<int, int> HttpRequest::set_content_type(const std::string &field_name,
											   const std::string &field_value) {
	return set_valid_media_type(field_name, field_value);
}
