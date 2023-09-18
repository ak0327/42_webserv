#include "RequestLine.hpp"

RequestLine::RequestLine():BaseKeyValueMap(){}

RequestLine::RequestLine(const RequestLine &other)
{
	this->_method = other.get_method();
	this->_target_page = other.get_target_page();
	this->_version = other.get_version();
}

void RequestLine::set_value(const std::string &line)
{
	std::istringstream	iss(line);
	std::string			word;

	iss >> word;
	this->_method = word;
	iss >> word;
	this->_target_page = word;
	iss >> word;
	this->_version = word;
}

RequestLine::~RequestLine(){}

std::string	RequestLine::get_method(void) const
{
	return (this->_method);
}

std::string RequestLine::get_target_page(void) const
{
	return (this->_target_page);
}

std::string	RequestLine::get_version(void) const
{
	return (this->_version);
}

std::string	RequestLine::show_requestline(void) const
{
	return ("request line info is >> " + this->_method + " | " + \
	"target page info is >> " + this->_target_page + " | " + \
	"version info is >> " + this->_version + " | ");
}
