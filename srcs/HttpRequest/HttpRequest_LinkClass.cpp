#include "HttpRequest.hpp"

LinkClass* HttpRequest::ready_LinkClass(std::map<std::string, std::map<std::string, std::string> > link_valuemap)
{
	return (new LinkClass(link_valuemap));
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
		uri = HandlingString::obtain_word_before_delimiter(line, ';');
		mapping_value = HandlingString::obtain_word_after_delimiter(line, ';');
		value_map[uri] = this->ready_mappingvalue(mapping_value);
	}
	this->_request_keyvalue_map[key] = this->ready_LinkClass(value_map);
}
