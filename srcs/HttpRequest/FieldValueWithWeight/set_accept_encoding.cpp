#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"

namespace {



}  // namespace

// todo: Accept-Encoding
/*
 Accept-Encoding  = #( codings [ weight ] )
 codings          = content-coding / "identity" / "*"
 content-coding   = token
 https://www.rfc-editor.org/rfc/rfc9110#field.accept-encoding
 */
// map<SingleFieldValue, weight>
Result<int, int> HttpRequest::set_accept_encoding(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// std::stringstream 	splited_by_commma(value);
	// std::string			skipping_nokeyword;
	// std::string			keyword;
	// std::string			line;
	// const std::string accept_encoding_keyset[] = {
	// 		"gzip", "compress", "deflate", "br", "*", "identity"
	// };
	// const std::set<std::string> httprequest_keyset
	// 		(
	// 				accept_encoding_keyset,
	// 				accept_encoding_keyset + sizeof(accept_encoding_keyset) / sizeof(accept_encoding_keyset[0])
	// 		);
	//
	// while(std::getline(splited_by_commma, line, ','))
	// {
	// 	if (StringHandler::obtain_withoutows_value(line) != "")
	// 	{
	// 		if (line.find(';') != std::string::npos)
	// 		{
	// 			if (std::count(line.begin(), line.end(), ';') != 1 || this->is_weightformat(line) == false)
	// 			{
	// 				this->_status_code = 400;
	// 				return Result<int, int>::ok(STATUS_OK);
	// 			}
	// 			keyword = StringHandler::obtain_word_before_delimiter(line, ';');
	// 		}
	// 		else
	// 			keyword = line;
	// 		keyword = StringHandler::obtain_withoutows_value(keyword);
	// 		if (httprequest_keyset.count(keyword) > 0)
	// 			skipping_nokeyword = skipping_nokeyword + line + ',';
	// 	}
	// }
	// this->_request_header_fields[key] = this->ready_ValueWeightArraySet(skipping_nokeyword.substr(0, skipping_nokeyword.length() - 1));
	return Result<int, int>::ok(STATUS_OK);
}
