#include <string>
#include "IsConfigFormat.hpp"

bool	IsConfigFormat::is_start_locationblock(const std::string &line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
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

// locationのスタートなら　location *.cgi {のように<OWS> location <OWS> <文字列->location path> <OWS> { <OWS>のみ許容
bool	IsConfigFormat::is_start_locationblock(const std::string &line, \
												std::string *config_location_path)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
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

// start_server -> <OWS> server <OWS> { <OWS>
bool	IsConfigFormat::is_start_serverblock(const std::string &line)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
	size_t	start_pos = 0;
	size_t	end_pos = 0;

	HandlingString::skip_no_ows(line_without_ows, &end_pos);
	if (line_without_ows.substr(start_pos, end_pos - start_pos) != "server" || end_pos == line_without_ows.length())
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	return (ConfigHandlingString::is_blockstart_endword(line_without_ows.substr(end_pos, line_without_ows.length() - end_pos)));
}

// location -> <OWS> (文字列->header) <OWS> {文字列->value}; <OWS>
// もしくは終了を表す　}　元のOWSはなくても許容 このis_型ではチェックのみ行う
bool	IsConfigFormat::is_locationblock_config(const std::string &line, \
													bool *in_location_block)
{
	// (文字列->header) <OWS> {文字列->value};
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
	size_t	end_pos = 0;

	if (ConfigHandlingString::is_block_end(line_without_ows))
	{
		*in_location_block = false;
		return true;
	}
	if (!(ConfigHandlingString::is_field_header(line_without_ows, &end_pos)))
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (!ConfigHandlingString::is_field_value(line_without_ows, &end_pos))
		return (false);
	if (line_without_ows.length() != end_pos + 1)
		return (false);
	return (true);
}

// location -> <OWS> (文字列->header) <OWS> {文字列->value}; <OWS>
// もしくは終了を表す　}　元のOWSはなくても許容
bool	IsConfigFormat::ready_locationblock_config(const std::string &line, \
													bool *in_location_block, \
LocationConfig *locationconfig, \
std::vector<std::string> *fieldkey_map)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
	// (文字列->header) <OWS> {文字列->value};
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;

	if (ConfigHandlingString::is_block_end(line_without_ows))
	{
		*in_location_block = false;
		return true;
	}
	if (!(ConfigHandlingString::ready_field_header(line_without_ows, &end_pos, &field_header)))
		return (false);
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (ConfigHandlingString::ready_field_value(line_without_ows, &end_pos, &field_value) == false)
		return (false);
	if (std::find(fieldkey_map->begin(), fieldkey_map->end(), field_header) != fieldkey_map->end())
		return (false);
	fieldkey_map->push_back(field_header);
	if (locationconfig->ready_locationblock_keyword(field_header, field_value) == false)
		return (false);
	return (true);
}

// <OWS> (文字列->header) <OWS> {文字列->value} ; <OWS>
// もしくはserver が終了する }
// もしくはlocationブロックのスタート
bool	IsConfigFormat::ready_serverblock_format(const std::string &line, \
													bool *in_server_block,
													ServerConfig *serverconfig, \
													std::vector<std::string> *field_key_vector)
{
	std::string	line_without_ows = HandlingString::obtain_without_ows_value(line);
	// (文字列->header) <OWS> {文字列->value};
	size_t	end_pos = 0;
	std::string	field_header;
	std::string	field_value;

	if (is_start_locationblock(line))
		return (true);
	if (ConfigHandlingString::is_block_end(line_without_ows))
	{
		*in_server_block = false;
		return true;
	}
	if (!(ConfigHandlingString::ready_field_header(line_without_ows, &end_pos, &field_header)))
		return (false);
	if (std::find(field_key_vector->begin(), field_key_vector->end(), field_header) != field_key_vector->end())
		return false;
	HandlingString::skip_ows(line_without_ows, &end_pos);
	if (ConfigHandlingString::ready_field_value(line_without_ows, &end_pos, &field_value) == false)
		return (false);
	if (serverconfig->ready_serverblock_keyword(field_header, field_value) == false)
	{
		std::cout << "serverconfig -> |" << field_header << "|" << field_value << "|" << std::endl;
		return (false);
	}
	field_key_vector->push_back(field_header);
	return (true);
}
