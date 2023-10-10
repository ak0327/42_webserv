#include "HttpRequest.hpp"

ValueMap* HttpRequest::ready_ValueMap(const std::string &value, char delimiter)
{
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(value);
	std::string							line;

	while(std::getline(ss, line, delimiter))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new ValueMap(value_map));
}

ValueMap* HttpRequest::ready_ValueMap(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new ValueMap(value_map));
}

ValueMap* HttpRequest::ready_ValueMap(const std::string &only_value, const std::string &value)
{
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

void	HttpRequest::set_alt_svc(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value);
}

void	HttpRequest::set_content_disponesition(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ';');
	while (std::getline(ss, line, ';'))
		except_onlyvalue_line = except_onlyvalue_line + line;
	this->_request_header_fields[key] = this->ready_ValueMap(only_value, except_onlyvalue_line);
}

void	HttpRequest::set_content_type(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ',');
	while (std::getline(ss, line, ','))
		except_onlyvalue_line = except_onlyvalue_line + line;
	this->_request_header_fields[key] = this->ready_ValueMap(only_value, except_onlyvalue_line);
}

void	HttpRequest::set_cookie(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value);
}

void	HttpRequest::set_forwarded(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value);
}

void	HttpRequest::set_keep_alive(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value, ',');
}

void	HttpRequest::set_proxy_authenticate(const std::string &key, const std::string &value)
{
	std::string re_line = value.substr(1);
	size_t	empty_position = re_line.find(' ');
	std::string	before_space_word = re_line.substr(0, empty_position);
	std::string	after_space_word = re_line.substr(empty_position + 1, re_line.length());

	this->_request_header_fields[key] = this->ready_ValueMap(before_space_word, after_space_word);
}

void	HttpRequest::set_set_cookie(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value);
}

void	HttpRequest::set_strict_transport_security(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueMap(value);
}
