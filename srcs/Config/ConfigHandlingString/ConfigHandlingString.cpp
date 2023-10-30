#include <vector>
#include <string>
#include "Config.hpp"
#include "ConfigHandlingString.hpp"
#include "HandlingString.hpp"

// bool ConfigHandlingString::is_ignore_line(const std::string &config_line)
// {
// 	std::string line_without_ows = HandlingString::obtain_without_ows_value(config_line);

// 	return (line_without_ows.empty() || line_without_ows[0] == '#');
// }

// bool ConfigHandlingString::is_block_end(const std::string &config_line)
// {
// 	std::string line_without_ows = HandlingString::obtain_without_ows_value(config_line);

// 	return (line_without_ows == "}");
// }

// bool ConfigHandlingString::is_block_start(const std::string &block_end_word)
// {
// 	return (block_end_word == "{");
// }

// int ConfigHandlingString::is_field_header(const std::string &config_line, size_t *pos)
// {
// 	std::string	line_trim_header;
// 	size_t tmp_pos = 0;

// 	HandlingString::skip_no_ows(config_line, pos);
// 	if (config_line[*pos] == '\0')
// 		return NO_FIELD_HEADER;

// 	line_trim_header = config_line.substr(*pos);
// 	HandlingString::skip_ows(line_trim_header, &tmp_pos);
// 	if (line_trim_header[tmp_pos] == '\0')
// 		return NO_FIELD_VALUE;
// 	return FIELD_HEADER_OK;
// }

// int	ConfigHandlingString::is_field_value(const std::string &config_line, size_t *pos)
// {
// 	std::string	field_value_word = config_line.substr(*pos, config_line.length() - *pos);

// 	if (field_value_word.empty() || field_value_word == ";")
// 		return NO_FIELD_VALUE;
// 	if (std::count(field_value_word.begin(), field_value_word.end(), ';') == 0)
// 		return NO_SEMICOLON;
// 	if (std::count(field_value_word.begin(), field_value_word.end(), ';') != 1)
// 		return MULTIPLE_SEMICOLON;
// 	if (field_value_word[field_value_word.length() - 1] != ';')
// 		return NO_LAST_SEMICOLON;
// 	while (config_line[*pos] != ';')  // valueの終了条件は必ずセミコロンが存在しているかどうかになる
// 		*pos = *pos + 1;
// 	if (HandlingString::is_ows(config_line[*pos - 1]))
// 		return (NOT_FIELD_VALUE_FORMAT);
// 	return (FIELD_VALUE_OK);
// }

bool ConfigHandlingString::show_error_message(const std::string &config_line,
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
            std::cerr << "FATAL ERROR" << std::endl;
    }
	return (false);
}

bool ConfigHandlingString::ready_boolean_field_value(const std::string &field_value)
{
	return field_value == "on";
}

int ConfigHandlingString::ready_int_field_value(const std::string &field_value)
{
	return (NumericHandle::str_to_int(field_value));
}

size_t ConfigHandlingString::ready_size_t_field_value(const std::string &field_value)
{
	return (static_cast<size_t>(NumericHandle::str_to_int(field_value)));
}

std::vector<std::string> ConfigHandlingString::ready_string_vector_field_value(const std::string &field_value)
{
	std::vector<std::string> ret_vector;
	std::string	value;
	std::istringstream values_splitted_by_empty(field_value);  // todo: unused -> rm
	std::string value_splitted_by_empty;   // todo: unused -> rm
	size_t value_start_pos = 0;
	size_t value_end_pos = 0;
	std::string	skip_ows_field_value = HandlingString::obtain_without_ows_value(field_value);

	while (skip_ows_field_value[value_start_pos] != '\0')
	{
		HandlingString::skip_no_ows(skip_ows_field_value, &value_end_pos);
		value = skip_ows_field_value.substr(value_start_pos, value_end_pos - value_start_pos);
		if (std::count(ret_vector.begin(), ret_vector.end(), value) == 0)
			ret_vector.push_back(value);
		HandlingString::skip_ows(skip_ows_field_value, &value_end_pos);
		value_start_pos = value_end_pos;
	}
	return (ret_vector);
}

int ConfigHandlingString::input_field_key_field_value(const std::string &config_line,
												LocationConfig *location_config)
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
	field_value = HandlingString::obtain_without_ows_value(
			line_without_ows.substr(field_value_start_pos, end_pos - field_value_start_pos));
	if (!location_config->set_field_header_field_value(field_header, field_value))
	{
		std::cerr << "serverconfig -> |" << field_header << "|" << field_value << "|" << std::endl;
		return (LOCATION_BLOCK_KEY_ALREADY_EXIST);
	}
	return (CONFIG_FORMAT_OK);
}

int ConfigHandlingString::input_field_key_field_value(const std::string &config_line,
												ServerConfig *server_config,
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
	field_value = HandlingString::obtain_without_ows_value(
			line_without_ows.substr(field_value_start_pos, end_pos - field_value_start_pos));
	if (!server_config->set_field_header_field_value(field_header, field_value))
	{
		std::cerr << "serverconfig -> |" << field_header << "|" << field_value << "|" << std::endl;
		return (SERVER_BLOCK_KEY_ALREADY_EXIST);
	}
	field_header_vector->push_back(field_header);
	return (CONFIG_FORMAT_OK);
}
