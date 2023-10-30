#include <string>
#include "Config.hpp"
#include "ConfigHandlingString.hpp"
#include "HandlingString.hpp"
#include "IsConfigFormat.hpp"

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
