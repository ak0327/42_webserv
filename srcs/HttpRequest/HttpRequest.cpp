#include "../includes/HttpRequest.hpp"

//constructor
HttpRequest::HttpRequest()
{
	//~~//
}

HttpRequest::HttpRequest(const std::string &other)
{

}

HttpRequest::HttpRequest(const HttpRequest& other)
{

}

HttpRequest& HttpRequest::operator=(const HttpRequest& other)
{

}

//destructor
HttpRequest::~HttpRequest()
{

}

//public関数
void HttpRequest::split_key_value(const std::string &other)
{
	size_t	colon_position = other.find(':');
	this->_httprequest_infs[this->obtain_key(other)] = this->obtain_value(other);
}

std::string HttpRequest::obtain_key(const std::string other)
{
	return other.substr(0, other.find(':'));
}

std::string HttpRequest::obtain_value(const std::string other)
{
	return other.substr(other.find(':') + 1);
}

std::map<std::string, std::string> HttpRequest::return_httprequest_infs(void) const
{
	return (this->_httprequest_infs);
}

std::string HttpRequest::return_value(const std::string key)
{
	return (this->_httprequest_infs[key]);
}