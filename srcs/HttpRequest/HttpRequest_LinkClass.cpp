#include "HttpRequest.hpp"

LinkClass* HttpRequest::ready_LinkClass(std::map<std::string, std::map<std::string, std::string> > link_valuemap)
{
	return (new LinkClass(link_valuemap));
}

std::map<std::string, std::string>	HttpRequest::ready_mappingvalue(const std::string &value_map_words)
{
	std::stringstream				ss(value_map_words);
	std::string						line;
	std::map<std::string, std::string>	words_mapping;
	std::string	key;
	std::string	val;
	std::string	skipping_first_empty;
	while(std::getline(ss, line, ';'))
	{
		skipping_first_empty = line.substr(1);
		key = HandlingString::obtain_word_before_delimiter(skipping_first_empty, '=');
		val = HandlingString::obtain_word_after_delimiter(skipping_first_empty, '=');
		words_mapping[key] = val;
	}
	return (words_mapping);
}

bool	is_list_form(const std::string &field_value_without_ows)
{
	size_t	same_field_value_start = 0;
	size_t	same_field_value_end = 0;
	while (same_field_value_end != std::string::npos)
	{
		same_field_value_end = field_value_without_ows.find(';', same_field_value_start);
		std::string	same_field_value = field_value_without_ows.substr(same_field_value_start, same_field_value_end - same_field_value_start);
		if (same_field_value_start != 0 && std::count(same_field_value.begin(), same_field_value.end(), '=') != 1)
			return (false);
		std::string	key = HandlingString::obtain_word_before_delimiter(same_field_value, '=');// = のようにkeyもvalueも空文字の場合は弾くのか
		std::string	value = HandlingString::obtain_word_after_delimiter(same_field_value, '=');
		if (HandlingString::obtain_withoutows_value(key) == "" || HandlingString::obtain_withoutows_value(value) == "")
			return (false);
		same_field_value_start = field_value_without_ows.find(';') + 1;
	}
	return (true);
}

void	HttpRequest::set_link(const std::string &key, const std::string &value)
{
	std::map<std::string, std::map<std::string, std::string> > value_map;
	std::stringstream	ss(value);
	std::string			line;
	std::string			uri;
	std::string			mapping_value;

	while(std::getline(ss, line, ','))
	{
		std::string	without_ows_line = HandlingString::obtain_withoutows_value(line);

		if (is_list_form(without_ows_line) == false)
		{
			this->_status_code = 400;
			return;
		}
		uri = HandlingString::obtain_word_before_delimiter(without_ows_line, ';');
		mapping_value = HandlingString::obtain_word_after_delimiter(without_ows_line, ';');
		value_map[uri] = this->ready_mappingvalue(mapping_value);
	}
	this->_request_keyvalue_map[key] = this->ready_LinkClass(value_map);
}
