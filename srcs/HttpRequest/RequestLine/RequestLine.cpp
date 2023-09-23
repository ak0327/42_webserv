#include "RequestLine.hpp"

RequestLine::RequestLine(){}

RequestLine::RequestLine(const RequestLine &other)
{
	this->_method = other.get_method();
	this->_request_target = other.get_target_page();
	this->_http_version = other.get_version();
}

void RequestLine::set_value(const std::string &line)
{
	// GET<SP>/index.html<SP>HTTP/1.1以外の一切を認めない
	std::istringstream	iss(line);
	std::string			word;

	// iss >> std::noskipws;
	iss >> word;
	this->_method = word;
	iss >> word;
	this->_request_target = word;
	iss >> word;
	this->_http_version = word;  // 空白やたぶを分別する理由が不明
}

RequestLine::~RequestLine(){}

std::string	RequestLine::get_method(void) const
{
	return (this->_method);
}

std::string RequestLine::get_target_page(void) const
{
	return (this->_request_target);
}

std::string	RequestLine::get_version(void) const
{
	return (this->_http_version);
}
