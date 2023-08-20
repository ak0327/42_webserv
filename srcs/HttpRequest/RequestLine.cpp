#include "../includes/RequestLine.hpp"

RequestLine::RequestLine()
{

}

void RequestLine::set_value(const std::string &line)
{
	std::istringstream	iss(input);
	std::string			word;

	iss >> word;
	this->_method = word;
	iss >> word;
	this->_target_page = word;
	iss >> word;
	this->_version = word;
}

RequestLine::~RequestLine()
{

}

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
	return (this->get_version);
}