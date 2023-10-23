#include "LocationConfig.hpp"

LocationConfig::LocationConfig():_autoindex(false), _chunked_transferencoding_allow(false), _server_tokens(1),
_client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024), _client_header_timeout(60),
_client_max_body_size(1024), _keepalive_requests(0), _keepalive_timeout(0), _default_type("application/octet-stream")
{}

LocationConfig::~LocationConfig(){}

bool	LocationConfig::ready_boolean_field_value(const std::string &field_value)
{
	if (field_value == "on")
		return (true);
	return (false);
}

int		LocationConfig::ready_int_field_value(const std::string &field_value){ return (NumericHandle::str_to_int(field_value)); }

size_t	LocationConfig::ready_size_t_field_value(const std::string &field_value)
{
	return (static_cast<size_t>(NumericHandle::str_to_int(field_value)));
}

std::vector<std::string>	LocationConfig::ready_string_vector_field_value(const std::string &field_value)
{
	std::vector<std::string>	anser_vector;
	std::istringstream	values_splited_by_empty(field_value);
	std::string	value_splited_by_empty;

	while (std::getline(values_splited_by_empty, value_splited_by_empty, ' '))
		anser_vector.push_back(value_splited_by_empty);
	return (anser_vector);
}

bool	LocationConfig::set_field_header_field_value(const std::string &field_header, \
														const std::string &field_value)
{
	std::vector<std::string>	field_headers;

	field_headers.push_back("autoindex");
	field_headers.push_back("chunked_transferencoding_allow");
	field_headers.push_back("server_tokens");
	field_headers.push_back("client_body_buffer_size");
	field_headers.push_back("client_body_timeout");
	field_headers.push_back("client_header_buffer_size");
	field_headers.push_back("client_header_timeout");
	field_headers.push_back("client_max_body_size");
	field_headers.push_back("keepalive_requests");
	field_headers.push_back("keepalive_timeout");
	field_headers.push_back("maxBodySize");
	field_headers.push_back("accesslog");
	field_headers.push_back("default_type");
	field_headers.push_back("errorlog");
	field_headers.push_back("port");
	field_headers.push_back("root");
	field_headers.push_back("allow_methods");
	field_headers.push_back("index");
	field_headers.push_back("server_name");
	field_headers.push_back("cgi_path");
	field_headers.push_back("alias");
	field_headers.push_back("upload_path");
	field_headers.push_back("error_page");
	field_headers.push_back("return");  // 未実装

	// if (std::find(field_headers.begin(), field_headers.end(), field_header) == field_headers.end())
	// {
	// 	return false;
	// } 当てはまらないものをfalseにするかどうか
	if (field_header == "listen")  // location内で認められていないワードはここではじく？
	{
		return (false);
	}
    if (field_header == "autoindex")
    {
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_autoindex = this->ready_boolean_field_value(field_value);
	}
    if (field_header ==  "chunked_transferencoding_allow")
    {
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_chunked_transferencoding_allow = this->ready_boolean_field_value(field_value);
	}
    if (field_header ==  "server_tokens")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_server_tokens = this->ready_int_field_value(field_value);
	}
	if (field_header ==  "client_body_buffer_size")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_buffer_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "client_body_timeout")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "client_header_buffer_size")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_buffer_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "client_header_timeout")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "client_max_body_size")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_max_body_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "keepalive_requests")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_requests = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "keepalive_timeout")
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header ==  "accesslog")
		this->_accesslog = field_value;
	if (field_header ==  "default_type")
		this->_default_type = field_value;
	if (field_header ==  "errorlog")
		this->_errorlog = field_value;
	if (field_header ==  "root")
		this->_root = field_value;
	if (field_header ==  "cgi_path")
		this->_cgi_path = field_value;
	if (field_header ==  "alias")
		this->_alias = field_value;
	if (field_header ==  "upload_path")
		this->_upload_path = field_value;
	if (field_header ==  "allow_methods")
		this->_allow_methods = ready_string_vector_field_value(field_value);
	if (field_header ==  "index")
		this->_index = ready_string_vector_field_value(field_value);
	if (field_header ==  "error_page")
		this->_errorpages = ready_string_vector_field_value(field_value);
	if (field_header ==  "server_name")
		this->_server_name = ready_string_vector_field_value(field_value);
	return (true);
}

bool	LocationConfig::get_autoindex(void){ return (this->_autoindex); }
bool	LocationConfig::get_chunked_transferencoding_allow(void){ return (this->_chunked_transferencoding_allow); }
int		LocationConfig::get_server_tokens(void){ return (this->_server_tokens); }
size_t	LocationConfig::get_client_body_buffer_size(void){ return (this->_client_body_buffer_size); }
size_t	LocationConfig::get_client_body_timeout(void){ return (this->_client_body_timeout); }
size_t	LocationConfig::get_client_header_buffer_size(void){ return (this->_client_header_buffer_size); }
size_t	LocationConfig::get_client_header_timeout(void){ return (this->_client_header_timeout); }
size_t	LocationConfig::get_client_max_body_size(void){ return (this->_client_max_body_size); }
size_t	LocationConfig::get_keepalive_requests(void){ return (this->_keepalive_requests); }
size_t	LocationConfig::get_keepalive_timeout(void){ return (this->_keepalive_timeout); }
std::string	LocationConfig::get_alias(void){ return (this->_alias); }
// error_page		LocationConfig::get	_errorpage_set;//これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
std::string	LocationConfig::get_accesslog(void){ return (this->_accesslog); }
std::string	LocationConfig::get_cgi_path(void){ return (this->_cgi_path); }
std::string	LocationConfig::get_default_type(void){ return (this->_default_type); }
std::string	LocationConfig::get_errorlog(void){ return (this->_errorlog); }
std::string	LocationConfig::get_upload_path(void){ return (this->_upload_path); }
std::string	LocationConfig::get_root(void){ return (this->_root); }
std::vector<std::string> LocationConfig::get_allow_methods(void){ return (this->_allow_methods); }
std::vector<std::string> LocationConfig::get_index(void){ return (this->_index); }
std::vector<std::string> LocationConfig::get_server_name(void){ return (this->_server_name); }
std::vector<std::string> LocationConfig::get_errorpages(void){ return (this->_errorpages); }

void	LocationConfig::clear_location_keyword()
{
	this->_autoindex = false;
	this->_chunked_transferencoding_allow = false;
	this->_server_tokens = 1;
	this->_client_body_buffer_size = 8000;
	this->_client_body_timeout = 60;
	this->_client_header_buffer_size = 1024;
	this->_client_header_timeout = 60;
	this->_keepalive_requests = 0;
	this->_keepalive_timeout = 0;
	this->_client_max_body_size = 1024;
	this->_alias = "";
	this->_accesslog = "";
	this->_cgi_path = "";
	this->_default_type = "application/octet-stream";
	this->_errorlog = "";
	this->_upload_path = "";
	this->_root = "";
	this->_allow_methods.clear();
	this->_index.clear();
	this->_server_name.clear();
	this->_errorpages.clear();
}

void LocationConfig::set_server_block_infs(const ServerConfig &other)
{
	this->set_autoindex(other.get_autoindex());
	this->set_chunked_transferencoding_allow(other.get_chunked_transferencoding_allow());
	this->set_server_tokens(other.get_server_tokens());
	this->set_client_body_buffer_size(other.get_client_body_buffer_size());
	this->set_client_header_timeout(other.get_client_header_timeout());
	this->set_client_max_body_size(other.get_client_max_body_size());
	this->set_keepaliverequests(other.get_keepalive_requests());
	this->set_keepalive_timeout(other.get_keepalive_timeout());
	this->set_accesslog(other.get_accesslog());
	this->set_default_type(other.get_default_type());
	this->set_default_type(other.get_default_type());
	this->set_errorlog(other.get_errorlog());
	this->set_root(other.get_root());
	this->set_allow_methods(other.get_allow_methods());
	this->_index.clear();
}
