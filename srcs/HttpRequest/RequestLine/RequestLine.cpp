#include "RequestLine.hpp"

RequestLine::RequestLine(){}

RequestLine::RequestLine(const RequestLine &other)
{
	this->_method = other.get_method();
	this->_request_target = other.get_target_page();
	this->_http_version = other.get_version();
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

void RequestLine::set_value(const std::string &line)
{
	int			i = 0;
	size_t		start_pos = 0;
	size_t		pos = 0;

	while (i != 3)
	{
		while (line[pos] != ' ' && pos != line.length() - 1)
			pos++;
		if (i == 0)
			this->_method = line.substr(start_pos, pos - start_pos);
		else if (i == 1)
			this->_request_target = line.substr(start_pos, pos - start_pos);
		else if (i == 2)
			this->_http_version = line.substr(start_pos, pos - start_pos);
		if (i != 2)
			pos++;
		start_pos = pos;
		i++;
	}
}
