#include "LocationConfig.hpp"

LocationConfig::LocationConfig():_autoindex(false), _chunked_transferencoding_allow(false), _server_tokens(1),
_client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024), _client_header_timeout(60),
_client_max_body_size(1048576), _keepaliverequests(0), _keepalive_timeout(0), _maxBodySize(1024), _default_type("application/octet-stream")
{

}

LocationConfig::~LocationConfig(){}

bool	LocationConfig::ready_boolean_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (true);
}

int		LocationConfig::ready_int_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (0);
}

size_t	LocationConfig::ready_size_t_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (1);
}

std::string		LocationConfig::ready_string_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return ("");
}

std::vector<std::string>	LocationConfig::ready_string_vector_fieldvalue(const std::string &field_value)
{
	std::vector<std::string>	anser_vector;
	std::cout << field_value << std::endl;
	return (anser_vector);
}

bool	LocationConfig::ready_locationblock_keyword(const std::string &field_key, const std::string &field_value)
{
	std::vector<std::string>	field_keys;

	field_keys.push_back("autoindex");
	field_keys.push_back("chunked_transferencoding_allow");
	field_keys.push_back("server_tokens");
	field_keys.push_back("client_body_buffer_size");
	field_keys.push_back("client_body_timeout");
	field_keys.push_back("client_header_buffer_size");
	field_keys.push_back("client_header_timeout");
	field_keys.push_back("client_max_body_size");
	field_keys.push_back("keepaliverequests");
	field_keys.push_back("keepalive_timeout");
	field_keys.push_back("maxBodySize");
	field_keys.push_back("accesslog");
	field_keys.push_back("default_type");
	field_keys.push_back("errorlog");
	field_keys.push_back("port");
	field_keys.push_back("root");
	field_keys.push_back("allow_methods");
	field_keys.push_back("index");
	field_keys.push_back("server_name");
	field_keys.push_back("cgi_path");
	field_keys.push_back("alias");
	field_keys.push_back("upload_path");
	field_keys.push_back("error_page");
	field_keys.push_back("return"); //未実装

	if (std::find(field_keys.begin(), field_keys.end(), field_key) == field_keys.end())
		return false;
    if (field_key == "autoindex")
    {
		this->_autoindex = this->ready_boolean_fieldvalue(field_value);
		return true;
	}
    else if (field_key ==  "chunked_transferencoding_allow")
    {
		this->_chunked_transferencoding_allow = this->ready_boolean_fieldvalue(field_value);
		return true;
	}
    else if (field_key ==  "server_tokens")
    {
		this->_server_tokens = this->ready_int_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "client_body_buffer_size")
    {
		this->_client_body_buffer_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "client_body_timeout")
    {
		this->_client_body_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "client_header_buffer_size")
    {
		this->_client_header_buffer_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "client_header_timeout")
    {
		this->_client_header_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "client_max_body_size")
    {
		this->_client_max_body_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "keepaliverequests")
    {
		this->_keepaliverequests = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "keepalive_timeout")
    {
		this->_keepalive_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "maxBodySize")
    {
		this->_maxBodySize = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "accesslog")
    {
		this->_accesslog = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "default_type")
    {
		this->_default_type = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "errorlog")
    {
		this->_errorlog = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "port")
    {
		this->_port = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "root")
    {
		this->_root = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "cgi_path")
	{
		this->_cgi_path = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "alias")
    {
		this->_alias = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "upload_path")
    {
		this->_upload_path = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "allow_methods")
    {
		this->_allowmethod_set = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "index")
    {
		this->_indexpage_set = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "error_page")
    {
		this->_errorpage_set = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	else if (field_key ==  "server_name")
    {
		this->_server_name = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	return (true);
}
