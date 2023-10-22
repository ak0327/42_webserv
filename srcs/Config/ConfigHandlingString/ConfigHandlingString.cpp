#include <string>
#include "ConfigHandlingString.hpp"

bool ConfigHandlingString::is_ignore_line(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	if (line_without_ows[0] == '#' || line_without_ows.empty())
		return (true);
	return (false);
}

bool ConfigHandlingString::is_block_end(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);

	return (line_without_ows == "}");
}

bool ConfigHandlingString::is_blockstart_endword(const std::string &block_end_word)
{
	// ブロックの始まりかどうか、という意味合いだけどどういう関数名がいいかわからない。。。
	return (block_end_word == "{");
}

bool	ConfigHandlingString::is_field_header(const std::string &config_line, size_t *pos)
{
	std::string	line_trim_header;
	size_t	check_tmp_num = 0;

	HandlingString::skip_no_ows(config_line, pos);
	if (config_line[*pos] == '\0')
		return ConfigHandlingString::show_error_message(config_line, NO_FIELD_VALUE);
	line_trim_header = config_line.substr(*pos, config_line.length() - *pos);
	HandlingString::skip_ows(line_trim_header, &check_tmp_num);
	if (line_trim_header[check_tmp_num] == '\0')
		return ConfigHandlingString::show_error_message(config_line, NO_FIELD_VALUE);
	return (true);
}

bool	ConfigHandlingString::is_field_value(const std::string &config_line, size_t *pos)
{
	std::string	field_value_word = config_line.substr(*pos, config_line.length() - *pos);
	if (field_value_word.empty() || field_value_word == ";")
		return ConfigHandlingString::show_error_message(config_line, NO_FIELD_VALUE);
	if (std::count(field_value_word.begin(), field_value_word.end(), ';') == 0)
		return ConfigHandlingString::show_error_message(config_line, NO_SEMICOLON);
	if (std::count(field_value_word.begin(), field_value_word.end(), ';') != 1)
		return ConfigHandlingString::show_error_message(config_line, MULTIPLE_SEMICOLON);
	if (field_value_word[field_value_word.length() - 1] != ';')
		return ConfigHandlingString::show_error_message(config_line, NO_LAST_SEMICOLON);
	while (config_line[*pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		*pos = *pos + 1;
	return (true);
}

bool ConfigHandlingString::show_error_message(const std::string &config_line, \
												const int &error_type)
{
	std::cerr << "*" << config_line << "*" << std::endl;
	switch (error_type)
	{
        case NO_FIELD_HEADER:
            std::cerr << "NO FIELD HEADE" << std::endl;
            break;
        case NO_FIELD_VALUE:
            std::cerr << "NO FIELD VALUE" << std::endl;
            break;
        case NO_LAST_SEMICOLON:
            std::cerr << "NO LAST SEMICOLON" << std::endl;
            break;
		case NO_SEMICOLON:
            std::cerr << "NO SEMICOLON" << std::endl;
            break;
		case MULTIPLE_SEMICOLON:
            std::cerr << "MULTIPLE SEMICOLON" << std::endl;
            break;
        default:
            std::cerr << "Invalid choice. Please choose a number between 1 and 3." << std::endl;
    }
	return (false);
}
