#include "HttpRequest.hpp"

ValueArraySet* HttpRequest::ready_ValueArraySet(const std::string &all_value)
{
	std::vector<std::string>	value_array;
	std::stringstream			ss(all_value);
	std::string					line;

	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::obtain_withoutows_value(line));
	return (new ValueArraySet(value_array));
}

// vector準備関数　わかりやすいように一時的に記載

void	HttpRequest::set_accept_ch(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_access_control_allow_headers(const std::string &key, const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (this->is_keyword_exist(HandlingString::obtain_withoutows_value(line)) == false)
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_access_control_allow_methods(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			word;

	while(std::getline(ss, line, ','))
	{
		if (line[0] == ' ')
			word = line.substr(1);
		else
			word = line;
		if (word != "GET" && word != "HEAD" && word != "POST" && word != "PUT" && word != "PUT" && word != "DELETE" \
		&& word != "CONNECT" && word != "OPTIONS" && word != "TRACE" && word != "PATCH")
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_access_control_expose_headers(const std::string &key, const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (this->is_keyword_exist(HandlingString::obtain_withoutows_value(line)) == false)
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_access_control_request_headers(const std::string &key, const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	std::string			word;

	while(std::getline(ss, line, ','))
	{
		if (line[0] == ' ')
			word = line.substr(1);
		else
			word = line;
		if (this->is_keyword_exist(HandlingString::obtain_withoutows_value(word)) == false)
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_allow(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			word;

	while(std::getline(ss, line, ','))
	{
		if (line[0] == ' ')
			word = line.substr(1);
		else
			word = line;
		if (word != "GET" && word != "HEAD" && word != "POST" && word != "PUT" && word != "PUT" && word != "DELETE" \
		&& word != "CONNECT" && word != "OPTIONS" && word != "TRACE" && word != "PATCH")
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_clear_site_data(const std::string &key, const std::string &value)
{
	// ダブルクオーテーションで囲う必要性があるようだが、"aaaa"", "bbb"みたいなことをされたとする
	// この場合にフォーマットが正しくないみたいなステータスコード を投げる？
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_content_encoding(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line != "gzip" && line != "compress" && line != "deflate" && line != "br")
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_content_language(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_if_match(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_if_none_match(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_transfer_encoding(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			skipping_firstemptyword;

	while(std::getline(ss, line, ','))
	{
		if (line[0] == ' ')
			skipping_firstemptyword = line.substr(1);
		else
			skipping_firstemptyword = line;
		if (skipping_firstemptyword != "gzip" && skipping_firstemptyword != "compress" && skipping_firstemptyword \
		!= "deflate" && skipping_firstemptyword != "gzip" && skipping_firstemptyword != "chunked")
			return;
	}
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_upgrade(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_vary(const std::string &key, const std::string &value)
{
	// headerのみしか許可しないのでは
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}

void	HttpRequest::set_www_authenticate(const std::string &key, const std::string &value)
{
	this->_request_keyvalue_map[key] = this->ready_ValueArraySet(value);
}
