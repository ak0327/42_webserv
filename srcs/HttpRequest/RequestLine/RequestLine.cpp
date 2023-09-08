#include "RequestLine.hpp"

RequestLine::RequestLine()
{

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
	return (this->_version);
}

void	RequestLine::show_requestline(void) const
{
	std::cout << "request line info is >> " << this->_method << std::endl;
	std::cout << "target page info is >> " << this->_target_page << std::endl;
	std::cout << "version info is >> " << this->_version << std::endl;
}