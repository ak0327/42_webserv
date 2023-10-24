#include <algorithm>
#include "Constant.hpp"
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



// todo: Accept-Encoding
/*
 Accept-Encoding  = #( codings [ weight ] )
 codings          = content-coding / "identity" / "*"
 content-coding   = token
 https://www.rfc-editor.org/rfc/rfc9110#field.accept-encoding
 */
// map<SingleFieldValue, weight>
Result<int, int> HttpRequest::set_accept_encoding(const std::string &key, const std::string &value)
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
		if (StringHandler::obtain_withoutows_value(line) != "")
		{
			if (line.find(';') != std::string::npos)
			{
				if (std::count(line.begin(), line.end(), ';') != 1 || this->is_weightformat(line) == false)
				{
					this->_status_code = 400;
					return Result<int, int>::ok(STATUS_OK);
				}
				keyword = StringHandler::obtain_word_before_delimiter(line, ';');
			}
			else
				keyword = line;
			keyword = StringHandler::obtain_withoutows_value(keyword);
			if (httprequest_keyset.count(keyword) > 0)
				skipping_nokeyword = skipping_nokeyword + line + ',';
		}
	}
	this->_request_header_fields[key] = this->ready_ValueWeightArraySet(skipping_nokeyword.substr(0, skipping_nokeyword.length() - 1));
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Accept-Language
/*
 Accept-Language = #( language-range [ weight ] )
 language-range  = (1*8ALPHA *("-" 1*8alphanum)) / "*"
 alphanum        = ALPHA / DIGIT
 https://datatracker.ietf.org/doc/html/rfc4647#section-2.1
 */
// map<SingleFieldValue, weight>
Result<int, int> HttpRequest::set_accept_language(const std::string &key, const std::string &value)
{
	std::stringstream 	splited_by_commma(value);
	std::string			skipping_nokeyword;
	std::string			keyword;
	std::string			line;

	while(std::getline(splited_by_commma, line, ','))
	{
		if (StringHandler::obtain_withoutows_value(line) != "")
		{
			if (line.find(';') != std::string::npos)
			{
				if (std::count(line.begin(), line.end(), ';') != 1 || this->is_weightformat(line) == false)
				{
					this->_status_code = 400;
					return Result<int, int>::ok(STATUS_OK);
				}
				keyword = StringHandler::obtain_word_before_delimiter(line, ';');
			}
		}
	}
	this->_request_header_fields[key] = this->ready_ValueWeightArraySet(value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: TE
/*
 TE                 = #t-codings
 t-codings          = "trailers" / ( transfer-coding [ weight ] )
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )
 https://www.rfc-editor.org/rfc/rfc9110#field.te
 */
// map<MapFieldValues, weight>
Result<int, int> HttpRequest::set_te(const std::string &key, const std::string &value)
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
			target_key = StringHandler::obtain_word_before_delimiter(line, ';');
			target_value = StringHandler::obtain_weight(StringHandler::obtain_word_after_delimiter(line, ';'));
			if (!(target_key == "compress" || target_key == "deflate" || target_key == "gzip" || target_key == "trailers"))
				return Result<int, int>::ok(STATUS_OK);
			if (StringHandler::is_positive_under_intmax_double(target_value) == false)
				return Result<int, int>::ok(STATUS_OK);
		}
		else
		{
			if (line[0] == ' ')
				line = line.substr(1);
			if (!(line == "compress" || line == "deflate" || line == "gzip" || line == "trailers"))
				return Result<int, int>::ok(STATUS_OK);
		}
	}
	this->_request_header_fields[key] = this->ready_ValueWeightArraySet(value);
	return Result<int, int>::ok(STATUS_OK);
}
