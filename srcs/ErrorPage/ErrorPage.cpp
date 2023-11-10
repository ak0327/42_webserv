#include "ErrorPage.hpp"

ErrorPage::ErrorPage(){}

// error pageのフォーマットは以下のとおり
// *(DIGIT DIGIT DIGIT) "=" (DIGIT DIGIT DIGIT) uri
// *(DIGIT DIGIT DIGIT) "=" uri
// *(DIGIT DIGIT DIGIT) uri
// uri = *("_" , ".", "~", "%", "/", "A~Z", "a~z", "0~9") A~Zとかってフォーマットで書くとしたらどう書くのか

void	ErrorPage::ready_code(const std::string &codes)
{
	size_t	status_code_start_pos = 0;
	size_t	status_code_end_pos = 0;

	while (target_string[status_code_start_pos] != '\0')
	{
		HandlingString::skip_no_ows(target_string, &status_code_end_pos);
		std::string	status_code = target_string.substr(status_code_start_pos, \
														status_code_end_pos - status_code_start_pos)
		this->_code.push_back(status_code);
		HandlingString::skip_ows(target_string, &status_code_end_pos);
		status_code_start_pos = status_code_end_pos;
		status_code_start_pos++;
	}
}

void	ErrorPage::ready_errorpage(const std::string &field_value)
{
	size_t	pos = 0;

	while (HandlingString::is_ows(field_value[pos]) || std::isdigit(field_value[pos]))
		pos++;
	std::string	status_codes = field_value.substr(pos);
	this->ready_code(status_codes);
	std::string	uri = field_value.substr(pos + 1, field_value.length() - (pos + 1));
	this->_uri = HandlingString::obtain_without_ows_value(uri);
}

void	ErrorPage::ready_errorpage_with_response(const std::string &field_value)
{
	std::string	field_value_without_ows = HandlingString::obtain_without_ows_value(field_value);
	size_t	pos = 0;

	while (field_value_without_ows[pos] != '=')
		pos++;
	std::string	codes = field_value_without_ows.substr(0, pos - 1, pos - 1);
	ready_code(codes);
	HandlingString::skip_ows(field_value_without_ows, &pos);
	if (std::isdigit(field_value_without_ows[pos]))
	{
		size_t	response_statuscode_start_pos = pos;
		while (std::isdigit(field_value_without_code[pos]))
			pos++;
		std::string	response_statuscode = field_value_without_ows.substr(response_statuscode_start_pos, \
																			pos);
		this->_response_statuscode = this->ready_code(response_statuscode);
	}
	HandlingString::skip_ows(field_value_without_ows, &pos);
	std::string	uri = field_value_without_ows.substr(pos, field_value_without_ows.length() - pos);
	this->_uri = HandlingString::obtain_without_ows_value(uri);
}

ErrorPage::ErrorPage(const std::string &field_value)
{
	if (std::count(field_value.begin(), field_value.end(), '=') != 0)
		ready_errorpage_with_response(field_value);
	else
		ready_errorpage(field_value);
}