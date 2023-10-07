#include "HttpRequest.hpp"

ValueWeightArraySet*	HttpRequest::ready_ValueWeightArraySet(const std::string &value)
{
	std::map<std::string, double>	value_map;
	std::stringstream				splited_by_commma(value);
	std::string						line;
	std::string						changed_line;
	std::string						target_value;

	while(std::getline(splited_by_commma, line, ','))
	{
		changed_line = StringHandler::obtain_withoutows_value(line);
		if (changed_line.find(';') != std::string::npos)
		{
			target_value = StringHandler::obtain_weight(StringHandler::obtain_word_after_delimiter(changed_line, ';'));
			value_map[StringHandler::obtain_word_before_delimiter(changed_line, ';')] = \
			StringHandler::str_to_double(StringHandler::obtain_weight(StringHandler::obtain_word_after_delimiter(changed_line, ';')));
		}
		else
			value_map[changed_line] = 1.0;
	}
	return (new ValueWeightArraySet(value_map));
}

void HttpRequest::set_accept(const std::string &key, const std::string &value)
{
	size_t							value_length = value.size();
	size_t							now_location = 0;
	std::stringstream				splited_by_commma(value);
	std::string						line;
	std::string						changed_line;

	char not_accept_encoding_keyset[] = {
		'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x10', \
		'\x0A', '\x0B', '\x0C', '\x0D', '\x0E', '\x0F', '\x10', '\x11', '\x12', '\x13', '\x14', \
		'\x15', '\x16', '\x17', '\x18', '\x19', '\x1A', '\x1B', '\x1C', '\x1D', '\x1E', '\x1F', \
		'(', ')', ':', '<', '>', '?', '@', '[', '\\', ']', '{', '}'
	};
	const std::set<char> not_accept_keyset
	(
		not_accept_encoding_keyset,
		not_accept_encoding_keyset + sizeof(not_accept_encoding_keyset) / sizeof(not_accept_encoding_keyset[0])
	);
	while (now_location != value_length - 1)
	{
		if (not_accept_keyset.count(value[now_location]) > 0)
			return;
		now_location++;
	}
	while(std::getline(splited_by_commma, line, ','))
	{
		if (line[0] == ' ')
			changed_line = line.substr(1);
		else
			changed_line = line;
		if (changed_line.find(';') != std::string::npos)
		{
			if (HandlingString::is_positive_under_intmax_double(HandlingString::obtain_weight(HandlingString::obtain_word_after_delimiter(changed_line, ';'))) == false)
				return;
		}
	}
	this->_request_keyvalue_map[key] = this->ready_ValueWeightArraySet(value);
}

void	HttpRequest::set_accept_charset(const std::string &key, const std::string &value)
{
	std::stringstream				splited_by_commma(value);
	std::string						line;
	std::string						changed_line;

	while(std::getline(splited_by_commma, line, ','))
	{
		if (line[0] == ' ')
			changed_line = line.substr(1);
		else
			changed_line = line;
		if (changed_line.find(';') != std::string::npos)
		{
			if (HandlingString::is_positive_under_intmax_double(HandlingString::obtain_weight(HandlingString::obtain_word_after_delimiter(changed_line, ';'))) == false)
				return;
		}
	}
	this->_request_keyvalue_map[key] = this->ready_ValueWeightArraySet(value);
}

void	HttpRequest::set_accept_encoding(const std::string &key, const std::string &value)
{
	std::stringstream 	splited_by_commma(value);
	std::string			skipping_nokeyword;
	std::string			keyword;
	std::string			line;
	const std::string accept_encoding_keyset[] = {
		"gzip", "compress", "deflate", "br", "*", "identity"
	};
	const std::set<std::string> httprequest_keyset
	(
		accept_encoding_keyset,
		accept_encoding_keyset + sizeof(accept_encoding_keyset) / sizeof(accept_encoding_keyset[0])
	);

	while(std::getline(splited_by_commma, line, ','))
	{
		if (HandlingString::obtain_withoutows_value(line) != "")
		{
			if (line.find(';') != std::string::npos)
			{
				if (std::count(line.begin(), line.end(), ';') != 1 || this->is_weightformat(line) == false)
				{
					this->_status_code = 400;
					return;
				}
				keyword = HandlingString::obtain_word_before_delimiter(line, ';');
			}
			else
				keyword = line;
			keyword = HandlingString::obtain_withoutows_value(keyword);
			if (httprequest_keyset.count(keyword) > 0)
				skipping_nokeyword = skipping_nokeyword + line + ',';
		}
	}
	this->_request_keyvalue_map[key] = this->ready_ValueWeightArraySet(skipping_nokeyword.substr(0, skipping_nokeyword.length() - 1));
}

void	HttpRequest::set_accept_language(const std::string &key, const std::string &value)
{
	std::stringstream 	splited_by_commma(value);
	std::string			skipping_nokeyword;
	std::string			keyword;
	std::string			line;

	while(std::getline(splited_by_commma, line, ','))
	{
		if (HandlingString::obtain_withoutows_value(line) != "")
		{
			if (line.find(';') != std::string::npos)
			{
				if (std::count(line.begin(), line.end(), ';') != 1 || this->is_weightformat(line) == false)
				{
					this->_status_code = 400;
					return;
				}
				keyword = HandlingString::obtain_word_before_delimiter(line, ';');
			}
		}
	}
	this->_request_keyvalue_map[key] = this->ready_ValueWeightArraySet(value);
}

void	HttpRequest::set_te(const std::string &key, const std::string &value)
{
	std::stringstream				splited_by_commma(value);
	std::string						line;
	std::string						target_key;
	std::string						target_value;

	while(std::getline(splited_by_commma, line, ','))
	{
		if (line.find(';') != std::string::npos)
		{
			if (line[0] == ' ')
				line = line.substr(1);
			target_key = HandlingString::obtain_word_before_delimiter(line, ';');
			target_value = HandlingString::obtain_weight(HandlingString::obtain_word_after_delimiter(line, ';'));
			if (!(target_key == "compress" || target_key == "deflate" || target_key == "gzip" || target_key == "trailers"))
				return;
			if (HandlingString::is_positive_under_intmax_double(target_value) == false)
				return;
		}
		else
		{
			if (line[0] == ' ')
				line = line.substr(1);
			if (!(line == "compress" || line == "deflate" || line == "gzip" || line == "trailers"))
				return;
		}
	}
	this->_request_keyvalue_map[key] = this->ready_ValueWeightArraySet(value);
}
