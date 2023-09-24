#ifndef SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_
#define SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_

# include <iostream>
# include <sstream>
# include <string>

class RequestLine
{
	private:
		std::string _method;
		std::string _request_target;
		std::string _http_version;
		RequestLine& operator=(const RequestLine &other);
		RequestLine(const RequestLine &other);
	public:
		RequestLine();
		~RequestLine();
		std::string	get_method(void) const;
		std::string get_target_page(void) const;
		std::string	get_version(void) const;
		void		set_value(const std::string &line);
};

#endif  // SRCS_HTTPREQUEST_REQUESTLINE_REQUESTLINE_HPP_
