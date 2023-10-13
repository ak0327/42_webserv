#include "Constant.hpp"
#include "HttpRequest.hpp"

ValueMap* HttpRequest::ready_ValueMap(const std::string &value, char delimiter) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(value);
	std::string							line;

	while(std::getline(ss, line, delimiter))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new ValueMap(value_map));
}

ValueMap* HttpRequest::ready_ValueMap(const std::string &value) {
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new ValueMap(value_map));
}

ValueMap* HttpRequest::ready_ValueMap(const std::string &only_value, const std::string &value) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(value);
	std::string							line;
	std::string							skipping_word;

	while(std::getline(ss, line, ';'))
	{
		skipping_word = StringHandler::obtain_withoutows_value(line);
		value_map[StringHandler::obtain_word_before_delimiter(skipping_word, '=')] \
		= StringHandler::obtain_withoutows_value(StringHandler::obtain_word_after_delimiter(skipping_word, '='));
	}
	return (new ValueMap(only_value, value_map));
}

// map準備関数

// todo: Content-Disposition
Result<int, int> HttpRequest::set_content_disponesition(const std::string &key, const std::string &value) {
	std::stringstream	ss(value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ';');
	while (std::getline(ss, line, ';'))
		except_onlyvalue_line = except_onlyvalue_line + line;
	_request_header_fields[key] = this->ready_ValueMap(only_value, except_onlyvalue_line);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Content-Type
Result<int, int> HttpRequest::set_content_type(const std::string &key, const std::string &value) {
	std::stringstream	ss(value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ',');
	while (std::getline(ss, line, ','))
		except_onlyvalue_line = except_onlyvalue_line + line;
	_request_header_fields[key] = this->ready_ValueMap(only_value, except_onlyvalue_line);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Cookie
Result<int, int> HttpRequest::set_cookie(const std::string &key, const std::string &value) {
	_request_header_fields[key] = this->ready_ValueMap(value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Forwarded
Result<int, int> HttpRequest::set_forwarded(const std::string &key, const std::string &value) {
	_request_header_fields[key] = this->ready_ValueMap(value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Keep-Alive
Result<int, int> HttpRequest::set_keep_alive(const std::string &key, const std::string &value) {
	_request_header_fields[key] = this->ready_ValueMap(value, ',');
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Set-Cookie
Result<int, int> HttpRequest::set_set_cookie(const std::string &key, const std::string &value) {
	_request_header_fields[key] = this->ready_ValueMap(value);
	return Result<int, int>::ok(STATUS_OK);
}
