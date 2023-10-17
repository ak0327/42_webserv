#ifndef	StatusText_HPP
#define StatusText_HPP

#include <string>

class StatusText
{
	private:
		std::string	_status_text;
		std::string	_body_text;
	public:
		StatusText(const std::string &status_text, const std::string &body_text);
		~StatusText();
		std::string	get_status_text(void) const;
		std::string	get_body_text(void) const;
}

#endif