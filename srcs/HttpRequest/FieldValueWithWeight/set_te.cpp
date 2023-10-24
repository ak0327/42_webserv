#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"

namespace {



}  // namespace

// todo: TE
/*
 TE                 = #t-codings
 t-codings          = "trailers" / ( transfer-coding [ weight ] )
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )
 https://www.rfc-editor.org/rfc/rfc9110#field.te
 */
// map<MapFieldValues, weight>
Result<int, int> HttpRequest::set_te(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// std::stringstream				splited_by_commma(value);
	// std::string						line;
	// std::string						target_key;
	// std::string						target_value;
	//
	// while(std::getline(splited_by_commma, line, ','))
	// {
	// 	if (line.find(';') != std::string::npos)
	// 	{
	// 		if (line[0] == ' ')
	// 			line = line.substr(1);
	// 		target_key = StringHandler::obtain_word_before_delimiter(line, ';');
	// 		target_value = StringHandler::obtain_weight(StringHandler::obtain_word_after_delimiter(line, ';'));
	// 		if (!(target_key == "compress" || target_key == "deflate" || target_key == "gzip" || target_key == "trailers"))
	// 			return Result<int, int>::ok(STATUS_OK);
	// 		if (StringHandler::is_positive_under_intmax_double(target_value) == false)
	// 			return Result<int, int>::ok(STATUS_OK);
	// 	}
	// 	else
	// 	{
	// 		if (line[0] == ' ')
	// 			line = line.substr(1);
	// 		if (!(line == "compress" || line == "deflate" || line == "gzip" || line == "trailers"))
	// 			return Result<int, int>::ok(STATUS_OK);
	// 	}
	// }
	// this->_request_header_fields[key] = this->ready_ValueWeightArraySet(value);
	return Result<int, int>::ok(STATUS_OK);
}
