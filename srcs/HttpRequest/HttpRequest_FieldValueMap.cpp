#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

namespace {

}  // namespace

////////////////////////////////////////////////////////////////////////////////

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &field_value, char delimiter) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(field_value);
	std::string							line;

	while(std::getline(ss, line, delimiter))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new FieldValueMap(value_map));
}

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &field_value) {
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(field_value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new FieldValueMap(value_map));
}

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &only_value, const std::string &field_value) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(field_value);
	std::string							line;
	std::string							skipping_word;

	while(std::getline(ss, line, ';'))
	{
		skipping_word = StringHandler::obtain_withoutows_value(line);
		value_map[StringHandler::obtain_word_before_delimiter(skipping_word, '=')] \
		= StringHandler::obtain_withoutows_value(StringHandler::obtain_word_after_delimiter(skipping_word, '='));
	}
	return (new FieldValueMap(only_value, value_map));
}


// 複数OK
// todo: Content-Disposition
// bnf??
Result<int, int> HttpRequest::set_content_disposition(const std::string &field_name,
													  const std::string &field_value) {
	std::stringstream	ss(field_value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ';');
	while (std::getline(ss, line, ';'))
		except_onlyvalue_line = except_onlyvalue_line + line;
	_request_header_fields[field_name] = this->ready_ValueMap(only_value,
															  except_onlyvalue_line);
	return Result<int, int>::ok(STATUS_OK);
}
