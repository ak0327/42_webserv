#include <string>
#include "Config.hpp"
#include "ConfigHandlingString.hpp"
#include "HandlingString.hpp"
#include "IsConfigFormat.hpp"

bool IsConfigFormat::is_empty_file(const std::string &config_file_name)
{
	std::ifstream config_lines(config_file_name.c_str());
	std::string	config_line;

	while (std::getline(config_lines, config_line, '\n'))
	{
		if ((IsConfigFormat::is_ignore_line(config_line)))
			continue;
		if (config_line.empty())
			continue;
		return (false);
	}
	return (true);
}

bool IsConfigFormat::is_ignore_line(const std::string &config_line)
{
	std::string line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	return (line_without_ows.empty() || line_without_ows[0] == '#');
}

bool IsConfigFormat::is_block_end(const std::string &config_line)
{
	std::string line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	return (line_without_ows == "}");
}

bool IsConfigFormat::is_block_start(const std::string &block_end_word)
{
	return (block_end_word == "{");
}

int IsConfigFormat::is_field_header(const std::string &config_line, size_t *pos)
{
	std::string	line_trim_header;
	size_t tmp_pos = 0;

	HandlingString::skip_no_ows(config_line, pos);
	if (config_line[*pos] == '\0')
		return NO_FIELD_HEADER;

	line_trim_header = config_line.substr(*pos);
	HandlingString::skip_ows(line_trim_header, &tmp_pos);
	if (line_trim_header[tmp_pos] == '\0')
		return NO_FIELD_VALUE;
	return FIELD_HEADER_OK;
}

int	IsConfigFormat::is_field_value(const std::string &config_line, size_t *pos)
{
	std::string	field_value_word = config_line.substr(*pos, config_line.length() - *pos);

	if (field_value_word.empty() || field_value_word == ";")
		return NO_FIELD_VALUE;
	if (std::count(field_value_word.begin(), field_value_word.end(), ';') == 0)
		return NO_SEMICOLON;
	if (std::count(field_value_word.begin(), field_value_word.end(), ';') != 1)
		return MULTIPLE_SEMICOLON;
	if (field_value_word[field_value_word.length() - 1] != ';')
		return NO_LAST_SEMICOLON;
	while (config_line[*pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		*pos = *pos + 1;
	if (HandlingString::is_ows(config_line[*pos - 1]))
		return (NOT_FIELD_VALUE_FORMAT);
	return (FIELD_VALUE_OK);
}

int IsConfigFormat::is_start_location_block(const std::string &config_line)
{
	return (is_start_location_block(config_line, NULL));
}

// int型に変更してエラーの種類を取得するようにする

int IsConfigFormat::is_start_location_block(const std::string &config_line,
											std::string *config_location_path)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	if (std::count(config_line.begin(), config_line.end(), '{') != 1)
		return (FORBIDDEN_WORD);
	bool is_printable = HandlingString::is_printable_content(config_line);
	if (!is_printable)
		return (NOT_PRINTABLE);

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "location"
	|| end_pos == line_without_ows.length())
		return (NOT_EXIST_KEYWORD_LOCATION);

	HandlingString::skip_ows(line_without_ows, &end_pos);
	start_pos = end_pos;
	HandlingString::skip_no_ows(line_without_ows, &end_pos);

	if (config_location_path != NULL)
	{
		*config_location_path = line_without_ows.substr(start_pos, end_pos - start_pos);
		if (!HandlingString::is_printable_content(*config_location_path)
		|| end_pos == line_without_ows.length())
			return (NOT_FIELD_KEY_PRINTABLE);
	}
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (!IsConfigFormat::is_block_start(line_without_ows.substr(end_pos)))
		return (NOT_ENDWORD_CURLY_BRACES);
	return (CONFIG_FORMAT_OK);
}

int	IsConfigFormat::is_start_server_block(const std::string &config_line, bool *in_server_block)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	if (std::count(config_line.begin(), config_line.end(), '{') != 1)
		return (FORBIDDEN_WORD);
	bool is_printable = HandlingString::is_printable_content(config_line);
	if (!is_printable)
		return (NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') == 0)
		return (NOT_CURLY_BRACES_EXIST);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') > 1)
		return (NOT_ONLY_CURLY_BRACES);
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "server"
	|| end_pos == line_without_ows.length())
		return (NOT_EXIST_KEYWORD_SERVER);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (IsConfigFormat::is_block_start(line_without_ows.substr(end_pos)))
	{
		*in_server_block = true;
		return (CONFIG_FORMAT_OK);
	}
	return (NOT_ENDWORD_CURLY_BRACES);
}

int	IsConfigFormat::is_location_block_format(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;
	int	action_result;

	if (!HandlingString::is_printable_content(line_without_ows))
		return (NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') != 0)
		return (NOT_START_CURLY_BRACES);
	action_result = IsConfigFormat::is_field_header(line_without_ows, &end_pos);
	if (action_result != FIELD_HEADER_OK)
		return (action_result);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	action_result = IsConfigFormat::is_field_value(line_without_ows, &end_pos);
	if (action_result != FIELD_VALUE_OK)
		return (action_result);
	if (line_without_ows.length() != end_pos + 1)
		return (NOT_LAST_WARD_SEMICOLON);
	return (CONFIG_FORMAT_OK);
}

int IsConfigFormat::is_server_block_format(const std::string &config_line,
										   std::vector<std::string> field_headers)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;
	int	action_result;

	if (!HandlingString::is_printable_content(line_without_ows))
		return (NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') != 0)
		return (NOT_START_CURLY_BRACES);
	action_result = IsConfigFormat::is_field_header(line_without_ows, &end_pos);
	if (action_result != CONFIG_FORMAT_OK)
		return (action_result);
	field_header = line_without_ows.substr(0, end_pos);
	if (std::find(field_headers.begin(), field_headers.end(), field_header) != field_headers.end())
		return SERVER_BLOCK_KEY_ALREADY_EXIST;
	HandlingString::skip_ows(line_without_ows, &end_pos);
	action_result = IsConfigFormat::is_field_value(line_without_ows, &end_pos);
	if (action_result != CONFIG_FORMAT_OK)
		return (action_result);
	return (CONFIG_FORMAT_OK);
}

bool IsConfigFormat::is_statuscodes(const std::string &target_string)
{
	size_t	status_code_start_pos = 0;
	size_t	status_code_end_pos = 0;

	while (target_string[status_code_start_pos] != '\0')
	{
		HandlingString::skip_no_ows(target_string, &status_code_end_pos);
		std::string	status_code = target_string.substr(status_code_start_pos, \
														status_code_end_pos - status_code_start_pos);
		if (NumericHandle::is_positive_and_under_intmax_int(status_code) == false)
			return (false);
		HandlingString::skip_ows(target_string, &status_code_end_pos);
		status_code_start_pos = status_code_end_pos;
	}
	return (true);
}

// uri = *("_" , ".", "~", "%", "/", "A~Z", "a~z", "0~9") A~Zとかってフォーマットで書くとしたらどう書くのか
bool IsConfigFormat::is_uri(const std::string &target_string)
{
	size_t	pos = 0;
	while (target_string[pos] != '\0')
	{
		if (!(std::isalpha(target_string[pos]) || std::isdigit(target_string[pos])))
		{
			if (target_string[pos] != '_' && target_string[pos] != '.' && target_string[pos] != '~' \
			&& target_string[pos] != '%' && target_string[pos] != '/')
				return false;
		}
		pos++;
	}
	return (true);
}

bool IsConfigFormat::is_errorpage(const std::string &field_value)
{
	size_t	pos = 0;

	while (HandlingString::is_ows(field_value[pos]) || std::isdigit(field_value[pos]))
		pos++;
	std::string	status_codes = field_value.substr(pos);
	if (IsConfigFormat::is_statuscodes(HandlingString::obtain_without_ows_value(status_codes)) == false)
		return (false);
	std::string	uri = field_value.substr(pos + 1, field_value.length() - (pos + 1));
	if (IsConfigFormat::is_uri(HandlingString::obtain_without_ows_value(uri)) == false)
		return (false);
	return (true);
}

bool	IsConfigFormat::is_errorpage_with_response(const std::string &field_value)
{
	std::string	field_value_without_ows = HandlingString::obtain_without_ows_value(field_value);
	size_t	pos = 0;

	while (field_value_without_ows[pos] != '=')
		pos++;
	std::string	code = field_value_without_ows.substr(pos - 1);
	if (IsConfigFormat::is_statuscodes(field_value_without_ows) == false)
		return (false);
	HandlingString::skip_ows(field_value_without_ows, &pos);
	if (std::isdigit(field_value_without_ows[pos]))
	{
		size_t	response_statuscode_start_pos = pos;
		while (std::isdigit(field_value_without_ows[pos]))
			pos++;
		std::string	response_statuscode = field_value_without_ows.substr(response_statuscode_start_pos, \
																			pos);
		if (IsConfigFormat::is_statuscodes(response_statuscode) == false)
		return (false);
	}
	HandlingString::skip_ows(field_value_without_ows, &pos);
	std::string	uri = field_value_without_ows.substr(pos, field_value_without_ows.length() - pos);
	if (IsConfigFormat::is_uri(HandlingString::obtain_without_ows_value(uri)) == false)
		return (false);
	return (true);
}

bool	IsConfigFormat::is_errorpage_format(const std::string &field_value)
{
	if (std::count(field_value.begin(), field_value.end(), '=') != 0)
		return is_errorpage_with_response(field_value);
	else
		return is_errorpage(field_value);
}
