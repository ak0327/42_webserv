#include "HttpRequest.hpp"

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &all_value)
{
	std::stringstream	ss(HandlingString::obtain_withoutows_value(all_value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, '/');
	std::getline(ss, second_value, '/');

	return (new TwoValueSet(first_value, second_value));
}

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &value, char delimiter)
{
	std::stringstream	ss(HandlingString::obtain_withoutows_value(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, delimiter);
	std::getline(ss, second_value, delimiter);
	return (new TwoValueSet(HandlingString::obtain_withoutows_value(first_value), HandlingString::obtain_withoutows_value(second_value)));
}

// twovalueset わかりやすいように

void	HttpRequest::set_authorization(const std::string &key, const std::string &value)
{
	// Digest username=<username>,realm="<realm>",uri="<url>",algorithm=<algorithm>,nonce="<nonce>",
	// ValueMapに変更
	this->_request_keyvalue_map[key] = this->ready_TwoValueSet(value, ' ');
}

void	HttpRequest::set_accept_post(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_TwoValueSet(value, ',');
}

void	HttpRequest::set_host(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_TwoValueSet(value);
}

void	HttpRequest::set_permission_policy(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_TwoValueSet(value, ',');
}

void	HttpRequest::set_proxy_authorization(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_TwoValueSet(value, ' ');
}
