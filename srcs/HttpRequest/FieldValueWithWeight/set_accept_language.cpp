#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueWithWeight.hpp"
#include "MediaType.hpp"

namespace {



}  // namespace

// todo: Accept-Language
/*
 Accept-Language = #( language-range [ weight ] )
 language-range  = (1*8ALPHA *("-" 1*8alphanum)) / "*"
 alphanum        = ALPHA / DIGIT
 https://datatracker.ietf.org/doc/html/rfc4647#section-2.1
 */
// map<SingleFieldValue, weight>
Result<int, int> HttpRequest::set_accept_language(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// std::stringstream 	splited_by_commma(value);
	// std::string			skipping_nokeyword;
	// std::string			keyword;
	// std::string			line;
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
	// 	}
	// }
	// this->_request_header_fields[key] = this->ready_ValueWeightArraySet(value);
	return Result<int, int>::ok(STATUS_OK);
}
