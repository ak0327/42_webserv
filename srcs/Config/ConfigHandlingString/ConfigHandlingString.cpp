#include <string>
#include "ConfigHandlingString.hpp"

bool ConfigHandlingString::is_ignore_line(const std::string &line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);

	if (line_without_ows[0] == '#' || line_without_ows.empty())
		return (true);
	return (false);
}

bool ConfigHandlingString::is_block_end(const std::string &line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);

	return (line_without_ows == "}");
}

bool ConfigHandlingString::is_blockstart_endword(const std::string &block_endword)
{
	return (block_endword == "{");
}

bool	ConfigHandlingString::is_field_header(const std::string &line, size_t *pos)
{
	std::string	line_trim_header;
	size_t	check_tmp_num = 0;

	HandlingString::skip_no_ows(line, pos);
	if (line[*pos] == '\0')
		return ConfigHandlingString::show_error_message(line, NO_FIELD_VALUE);
	line_trim_header = line.substr(*pos, line.length() - *pos);
	HandlingString::skip_ows(line_trim_header, &check_tmp_num);
	if (line_trim_header[check_tmp_num] == '\0')
		return ConfigHandlingString::show_error_message(line, NO_FIELD_VALUE);
	return (true);
}

bool	ConfigHandlingString::is_field_value(const std::string &line, size_t *pos)
{
	if (line.empty() || line == ";")
		return ConfigHandlingString::show_error_message(line, NO_FIELD_VALUE);
	if (std::count(line.begin(), line.end(), ';') == 0)
		return ConfigHandlingString::show_error_message(line, NO_SEMICOLON);
	if (std::count(line.begin(), line.end(), ';') != 1)
		return ConfigHandlingString::show_error_message(line, MULTIPLE_SEMICOLON);
	if (line[line.length() - 1] != ';')
		return ConfigHandlingString::show_error_message(line, NO_LAST_SEMICOLON);
	while (line[*pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
		*pos = *pos + 1;
	return (true);
}

bool	ConfigHandlingString::ready_field_header(const std::string &line, \
													size_t *end_pos, \
													std::string *field_header)
{
	if (line.empty())
		return ConfigHandlingString::show_error_message(line, NO_FIELD_HEADER);
	HandlingString::skip_no_ows(line, end_pos);
	if (*end_pos == line.length())  // headerの存在確認を行う必要があればここで行う headerしか存在しない場合のチェックは必要
		return ConfigHandlingString::show_error_message(line, NO_FIELD_VALUE);
	*field_header = line.substr(0, *end_pos);
	return (true);
}

bool	ConfigHandlingString::ready_field_value(const std::string &line, \
													size_t *end_pos, \
													std::string *field_value)
{
	size_t start_pos = *end_pos;

	if (std::count(line.begin(), line.end(), ';') == 0)
		return ConfigHandlingString::show_error_message(line, NO_SEMICOLON);
	if (std::count(line.begin(), line.end(), ';') != 1)
		return ConfigHandlingString::show_error_message(line, MULTIPLE_SEMICOLON);
	while (line[*end_pos] != ';' && line[*end_pos] != '\0')
		*end_pos = *end_pos + 1;
	if (start_pos == *end_pos || line[*end_pos] != ';')
		return ConfigHandlingString::show_error_message(line, NO_SEMICOLON);
	*field_value = line.substr(start_pos, *end_pos - start_pos);
	if (*field_value == ";")  // "  key ; "のようにvalueがない場合はじく
		return ConfigHandlingString::show_error_message(line, NO_FIELD_VALUE);
	return (true);
}

bool ConfigHandlingString::show_error_message(const std::string &line, \
												const int &error_type)
{
	std::cerr << "*" << line << "*" << std::endl;
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
