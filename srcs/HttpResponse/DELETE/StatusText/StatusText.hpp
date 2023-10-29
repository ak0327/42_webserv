#ifndef	SRCS_HTTPRESPONSE_DELETE_STATUSTEXT_STATUSTEXT_HPP_
#define SRCS_HTTPRESPONSE_DELETE_STATUSTEXT_STATUSTEXT_HPP_

#include <string>

class StatusText
{
	private:
		std::string	_status_text;
		std::string	_body_text;
	public:
		StatusText();
		StatusText(const std::string &status_text, const std::string &body_text);
		~StatusText();
		std::string	get_status_text(void) const;
		std::string	get_body_text(void) const;
};

#endif  // SRCS_HTTPRESPONSE_DELETE_STATUSTEXT_STATUSTEXT_HPP_
