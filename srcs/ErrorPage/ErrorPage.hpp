#ifndef ErrorPage_HPP
#define ErrorPage_HPP

#include <vector>
#include <string>
#include "../HandlingString/HandlingString.hpp"

class ErrorPage
{
	private:
		size_t	_response_statuscode;
		std::string	_response_location;
		std::string	_uri;
		std::vector<size_t> _code;
		void	ready_errorpage_with_response(const std::string &field_value);
		void	ready_errorpage(const std::string &field_value);
		void	ready_response_statuscode(const std::string &field_value_without_code);
		void	ready_response_location(const std::string &field_value_without_code);
		void	ready_code(const std::string &codes);
	public:
		ErrorPage();
		ErrorPage(const std::string &field_value);
		ErrorPage(const ErrorPage &other);
		ErrorPage& operator=(const ErrorPage &other);
		~ErrorPage();

		std::string	get_response_location() const;
		std::string	get_uri() const;
		size_t	get_response_statuscode() const;
}

#endif