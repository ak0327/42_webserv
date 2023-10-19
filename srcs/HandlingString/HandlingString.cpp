#include "HandlingString.hpp"


bool	HandlingString::is_endl_semicolon_and_no_inner_semicoron(const std::string &word)
{
	size_t	pos = 0;
	size_t	semicolon_count = 0;

	while (word[pos] != '\0')
	{
		if (word[pos] == ';')
			semicolon_count++;
		pos++;
	}
	if (semicolon_count != 1)
		return (false);
	if (word[pos - 1] != ';')
		return (false);
	return (true);
}

bool HandlingString::is_ows(const char &c)
{
	return c == ' ' || c == '\t';
}

bool	HandlingString::is_printable_content(const std::string &value)
{
	size_t	value_length = value.length();
	size_t	pos = 0;

	while (pos != value_length)
	{
		if (isprint(value[pos]) == false)
			return (false);
		pos++;
	}
	return (true);
}

std::string	HandlingString::skip_lastsemicolon(const std::string &word)
{
	return word.substr(0, word.find(';'));
}

std::string HandlingString::obtain_unquote_str(const std::string &quoted_str)
{
	return quoted_str.substr(1, quoted_str.length() - 2);
}

std::string HandlingString::obtain_without_ows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows == "")
		return "";
	while (is_ows(field_value_with_ows[before_pos]) == true && before_pos != field_value_with_ows.length())
		before_pos++;
	while (is_ows(field_value_with_ows[after_pos]) == true && after_pos != 0)
		after_pos--;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}

void HandlingString::skip_ows(const std::string &line, size_t *pos)
{
	while (HandlingString::is_ows(line[*pos]) && line[*pos] != '\0')
		*pos = *pos + 1;
}

void HandlingString::skip_no_ows(const std::string &line, size_t *pos)
{
	while (!(HandlingString::is_ows(line[*pos])) && line[*pos] != '\0')
		*pos = *pos + 1;
}

bool HandlingString::is_field_value(const std::string &line, size_t *pos)
{
	if (line.empty() || line == ";")
		return (false);
	if (std::count(line.begin(), line.end(), ';') != 1)
		return (false);
	if (line[line.length() - 1] != ';')
		return (false);
	while (line[*pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		*pos = *pos + 1;
	return (true);
}
