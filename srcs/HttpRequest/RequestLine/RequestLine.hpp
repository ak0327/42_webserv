#ifndef SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_
#define SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_

#include <string>
#include <iostream>
#include <sstream>

class RequestLine
{
	private:
		std::string _method;
		std::string _target_page;
		std::string _version;
		RequestLine(const RequestLine &other);
		RequestLine& operator=(const RequestLine &other);
	public:
		RequestLine();
		~RequestLine();
		void		set_value(const std::string &line);
		std::string	get_method(void) const;
		std::string get_target_page(void) const;
		std::string	get_version(void) const;

		std::string	show_requestline(void) const;
};

#endif  // SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_
