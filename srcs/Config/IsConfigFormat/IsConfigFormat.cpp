#include <string>
#include "IsConfigFormat.hpp"

bool	IsConfigFormat::is_start_location_block(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "location" || end_pos == line_without_ows.length())
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	start_pos = end_pos;
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	start_pos = end_pos;
	return (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)));
}

bool	IsConfigFormat::is_start_location_block(const std::string &config_line, \
												std::string *config_location_path)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "location" || end_pos == line_without_ows.length())
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	start_pos = end_pos;
	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	*config_location_path = line_without_ows.substr(start_pos, end_pos - start_pos);
	if (!HandlingString::is_printable_content(*config_location_path) || end_pos == line_without_ows.length())
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	return (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)));
}

bool	IsConfigFormat::is_start_server_block(const std::string &config_line, bool *in_server_block)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (std::count(line_without_ows.begin(), line_without_ows.end(), '{') != 1)
		return (false);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "server" || end_pos == line_without_ows.length())
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)))
	{
		*in_server_block = true;
		return (true);
	}
	return (false);
}

bool	IsConfigFormat::is_location_block_format(const std::string &config_line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;

	if (!(ConfigHandlingString::is_field_header(line_without_ows, &end_pos)))
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (!ConfigHandlingString::is_field_value(line_without_ows, &end_pos))
		return (false);
	if (line_without_ows.length() != end_pos + 1)
		return (false);
	return (true);
}

bool	IsConfigFormat::do_input_field_key_field_value(const std::string	&config_line, \
															LocationConfig	*location_config, \
												std::vector<std::string>	*field_header_vector)
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
		return (false);
	}
	field_header_vector->push_back(field_header);
	return (true);
}

bool	IsConfigFormat::do_input_field_key_field_value(const std::string &config_line, \
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
		return (false);
	}
	field_header_vector->push_back(field_header);
	return (true);
}

bool	IsConfigFormat::is_server_block_format(const std::string &config_line, \
													std::vector<std::string> field_headers)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(config_line);
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;
	bool		is_format = false;

	is_format = ConfigHandlingString::is_field_header(line_without_ows, &end_pos);
	if (is_format == false)
		return (false);
	field_header = line_without_ows.substr(0, end_pos);
	if (std::find(field_headers.begin(), field_headers.end(), field_header) != field_headers.end())
		return false;
	HandlingString::skip_ows(line_without_ows, &end_pos);
	is_format = ConfigHandlingString::is_field_value(line_without_ows, &end_pos);
	if (is_format == false)
		return (false);
	return (true);
}

