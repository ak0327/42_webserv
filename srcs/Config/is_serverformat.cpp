// 命名はもう少し考えた方が良い？　

#include "Config.hpp"

//serverのスタートなら server {のように<OWS><server><OWS><{>のみ許容

std::vector<std::string>	obtain_field_values(const std::string &line_with_ows) // <OWS><string><OWS><string><OWS>...の時に<string>を取る関数と名付けたいが、命名不適の可能性大
{
	size_t					start_pos = 0;
	size_t					end_pos;
	std::string				trim_leading_trailing_ows = HandlingString::obtain_withoutows_value(line_with_ows);
	std::vector<std::string>	field_values;

	while (true)
	{
		start_pos = end_pos;
		while !(HandlingString::is_ows(trim_leading_trailing_ows[end_pos]))
			end_pos++;
		field_values.push_back(trim_leading_trailing_ows.substr(start_pos, end_pos - start_pos + 1));
		if (end_pos == trim_leading_trailing_ows.length())
			return field_values;
		while (HandlingString::is_ows(trim_leading_trailing_ows[end_pos]))
		{
			end_pos++;
			if (end_pos == trim_leading_trailing_ows.length())
				return field_values;
		}
		end_pos++;
	}
	return (field_values);
}

bool	Config::is_server_start_format(const std::string &line);
{
	std::string		line_without_ows = HandlingString::obtain_withoutows_value(line);
	std::ifstream	server_parts(line_without_ows);  //  `server {`
	std::string		server_part;
	int				parts_counter = 0;

	while(std::getline(server_parts, server_part, ' '))
	{
		switch (parts_counter)
		{
			case 0:
				if (server_part != "location")
					return false;
				else
					break;
			case 1:
				if (server_part != "{")
					return false;
				else
					break;
			default:
				return (false);
		}
		parts_counter++;
	}
	return (true);
}

//server内部なら　header<SP>*{文字列}<;>を許容　が、空白が一つかは不明 文字列内に関しても不明

bool	Config::is_server_content_format(const std::string &line);
{
	std::string		line_without_ows = HandlingString::obtain_withoutows_value(line);
	std::ifstream	server_parts(line_without_ows);  //  `server {`
	std::string		server_part;
	int				parts_counter = 0;

	while(std::getline(server_parts, server_part, ' '))
	{
		switch (parts_counter)
		{
			case 0:
				if (server_part != "location")
					return false;
				else
					break;
			case 1:
				if (server_part != "{")
					return false;
				else
					break;
			default:
				return (false);
		}
		parts_counter++;
	}
	return (true);
}
