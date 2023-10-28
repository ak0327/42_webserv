#include <string>
#include "IsConfigFormat.hpp"

int	IsConfigFormat::is_start_location_block(const std::string &config_line)
{
	return (is_start_location_block(config_line, NULL));
}

// int型に変更してエラーの種類を取得するようにする

int	IsConfigFormat::is_start_location_block(const std::string &config_line, \
												std::string *config_location_path)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	if (std::count(config_line.begin(), config_line.end(), '{') != 1)
		return (IS_FORBIDDEN_WORD);
	bool is_printable = HandlingString::is_printable_content(config_line);
	if (is_printable == false)
		return (IS_NOT_PRINTABLE);
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "location" || end_pos == line_without_ows.length())
		return (IS_NOT_EXIST_KEYWORD_LOCATION);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	start_pos = end_pos;
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (config_location_path != NULL)
	{
		*config_location_path = line_without_ows.substr(start_pos, end_pos - start_pos);
		if (!HandlingString::is_printable_content(*config_location_path) || end_pos == line_without_ows.length())
			return (IS_NOT_FIELD_KEY_PRINTABLE);
	}
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)) == false)
		return (IS_NOT_ENDWORD_CURLY_BRACES);
	return (IS_OK);
}

int	IsConfigFormat::is_start_server_block(const std::string &config_line, bool *in_server_block)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	if (std::count(config_line.begin(), config_line.end(), '{') != 1)
		return (IS_FORBIDDEN_WORD);
	bool is_printable = HandlingString::is_printable_content(config_line);
	if (is_printable == false)
		return (IS_NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') == 0)
		return (IS_NOT_CURLY_BRACES_EXIST);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') > 1)
		return (IS_NOT_ONLY_CURLY_BRACES);
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "server" || end_pos == line_without_ows.length())
		return (IS_NOT_EXIST_KEYWORD_SERVER);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)))
	{
		*in_server_block = true;
		return (IS_OK);
	}
	return (IS_NOT_ENDWORD_CURLY_BRACES);
}

int	IsConfigFormat::is_location_block_format(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;
	int	action_result = IS_OK;

	if (HandlingString::is_printable_content(line_without_ows) == false)
		return (IS_NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') != 0)
		return (IS_NOT_START_CURLY_BRACES);
	action_result = ConfigHandlingString::is_field_header(line_without_ows, &end_pos);
	if (action_result != IS_OK)
		return (action_result);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	action_result = ConfigHandlingString::is_field_value(line_without_ows, &end_pos);
	if (action_result != IS_OK)
		return (action_result);
	if (line_without_ows.length() != end_pos + 1)
		return (IS_NOT_LAST_WARD_SEMICOLON);
	return (IS_OK);
}

int	IsConfigFormat::input_field_key_field_value(const std::string	&config_line, \
															LocationConfig	*location_config)
{
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;
	size_t	field_value_start_pos;
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	field_header = line_without_ows.substr(0, end_pos);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	field_value_start_pos = end_pos;
	while (line_without_ows[end_pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		end_pos++;
	field_value = HandlingString::obtain_without_ows_value(line_without_ows.substr(field_value_start_pos, \
											end_pos - field_value_start_pos));
	if (location_config->set_field_header_field_value(field_header, field_value) == false)
	{
		std::cout << "serverconfig -> |" << field_header << "|" << field_value << "|" << std::endl;
		return (IS_LOCATION_BLOCK_KEY_ALREADY_EXIST);
	}
	return (IS_OK);
}

int	IsConfigFormat::input_field_key_field_value(const std::string &config_line, \
														ServerConfig *server_config, \
														std::vector<std::string> *field_header_vector)
{
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;
	size_t	field_value_start_pos;
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	field_header = line_without_ows.substr(0, end_pos);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	field_value_start_pos = end_pos;
	while (line_without_ows[end_pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		end_pos++;
	field_value = HandlingString::obtain_without_ows_value(line_without_ows.substr(field_value_start_pos, \
											end_pos - field_value_start_pos));
	if (server_config->set_field_header_field_value(field_header, field_value) == false)
	{
		std::cout << "serverconfig -> |" << field_header << "|" << field_value << "|" << std::endl;
		return (IS_SERVER_BLOCK_KEY_ALREADY_EXIST);
	}
	field_header_vector->push_back(field_header);
	return (IS_OK);
}

int	IsConfigFormat::is_server_block_format(const std::string &config_line, \
													std::vector<std::string> field_headers)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;
	int	action_result = IS_OK;

	if (HandlingString::is_printable_content(line_without_ows) == false)
		return (IS_NOT_PRINTABLE);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') != 0)
		return (IS_NOT_START_CURLY_BRACES);
	action_result = ConfigHandlingString::is_field_header(line_without_ows, &end_pos);
	if (action_result != IS_OK)
		return (action_result);
	field_header = line_without_ows.substr(0, end_pos);
	if (std::find(field_headers.begin(), field_headers.end(), field_header) != field_headers.end())
		return IS_SERVER_BLOCK_KEY_ALREADY_EXIST;
	HandlingString::skip_ows(line_without_ows, &end_pos);
	action_result = ConfigHandlingString::is_field_value(line_without_ows, &end_pos);
	if (action_result != IS_OK)
		return (action_result);
	return (IS_OK);
}

