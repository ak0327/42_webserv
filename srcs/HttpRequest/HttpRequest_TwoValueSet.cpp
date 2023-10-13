#include <algorithm>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &all_value)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(all_value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, '/');
	std::getline(ss, second_value, '/');

	return (new TwoValueSet(first_value, second_value));
}

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &value, char delimiter)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, delimiter);
	std::getline(ss, second_value, delimiter);
	return (new TwoValueSet(HttpMessageParser::obtain_withoutows_value(first_value), HttpMessageParser::obtain_withoutows_value(second_value)));
}

// authorizationはちょっと格納方法変えるかもしれない
// todo: Authorization
void	HttpRequest::set_authorization(const std::string &key, const std::string &value)
{
	// Digest username=<username>,realm="<realm>",uri="<url>",algorithm=<algorithm>,nonce="<nonce>",
	// ValueMapに変更
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ' ');
}

// todo: Accept-Post
void	HttpRequest::set_accept_post(const std::string &key, const std::string &value)
{
	if (std::count(value.begin(), value.end(), ',') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ','));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ','));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return;
		}
	}
	else if (std::count(value.begin(), value.end(), ',') > 1)
	{
		this->_status_code = 400;
		return;
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ',');
}

// todo: Host
void	HttpRequest::set_host(const std::string &key, const std::string &value)
{
	std::string	first_value;
	std::string	second_value;

	if (std::count(value.begin(), value.end(), ':') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ':'));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ':'));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return;
		}
	}
	else if (std::count(value.begin(), value.end(), ':') > 1)
	{
		this->_status_code = 400;
		return;
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ':');
}

// todo: Permission-Policy
void	HttpRequest::set_permission_policy(const std::string &key, const std::string &value)
{
	if (std::count(value.begin(), value.end(), ',') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ','));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ','));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return;
		}
	}
	else if (std::count(value.begin(), value.end(), ',') > 1)
	{
		this->_status_code = 400;
		return;
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ',');
}

// todo: Proxy-Authorization
void	HttpRequest::set_proxy_authorization(const std::string &key, const std::string &value)
{
	if (std::count(value.begin(), value.end(), ' ') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(value, ' '));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(value, ' '));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return;
		}
	}
	else if (std::count(value.begin(), value.end(), ' ') > 1)
	{
		this->_status_code = 400;
		return;
	}
	this->_request_header_fields[key] = this->ready_TwoValueSet(value, ' ');
}
