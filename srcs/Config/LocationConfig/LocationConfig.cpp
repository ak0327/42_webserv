#include "LocationConfig.hpp"

LocationConfig::LocationConfig():_autoindex(false), _chunked_transferencoding_allow(false), _server_tokens(1),
_client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024), _client_header_timeout(60),
_client_max_body_size(1024), _keepalive_requests(0), _keepalive_timeout(0), _default_type("application/octet-stream")
{}

LocationConfig::~LocationConfig(){}

bool	LocationConfig::set_field_header_field_value(const std::string &field_header, \
														const std::string &field_value)
{
	std::vector<std::string>	field_headers;

	field_headers.push_back(AUTOINDEX);
	field_headers.push_back(CHUNKED_TRANSFERENCODING_ALLOW);
	field_headers.push_back(SERVER_TOKENS);
	field_headers.push_back(CLIENT_BODY_BUFFER_SIZE);
	field_headers.push_back(CLIENT_BODY_TIMEOUT);
	field_headers.push_back(CLIENT_HEADER_BUFFER_SIZE);
	field_headers.push_back(CLIENT_HEADER_TIMEOUT);
	field_headers.push_back(CLIENT_MAX_BODY_SIZE);
	field_headers.push_back(KEEPALIVE_REQUESTS);
	field_headers.push_back(KEEPALIVE_TIMEOUT);
	field_headers.push_back(ACCESSLOG);
	field_headers.push_back(DEFAULT_TYPE);
	field_headers.push_back(ERRORLOG);
	field_headers.push_back(ROOT);
	field_headers.push_back(ALLOW_METHODS);
	field_headers.push_back(INDEX);
	field_headers.push_back(SERVER_NAME);
	field_headers.push_back(CGI_PATH);
	field_headers.push_back(ALIAS);
	field_headers.push_back(UPLOAD_PATH);

	if (std::find(field_headers.begin(), field_headers.end(), field_header) == field_headers.end())
	{
		return false;
	}
    if (field_header == AUTOINDEX)
    {
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_autoindex = ConfigHandlingString::ready_boolean_field_value(field_value);
	}
    if (field_header ==  CHUNKED_TRANSFERENCODING_ALLOW)
    {
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_chunked_transferencoding_allow = ConfigHandlingString::ready_boolean_field_value(field_value);
	}
    if (field_header ==  SERVER_TOKENS)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_server_tokens = ConfigHandlingString::ready_int_field_value(field_value);
	}
	if (field_header ==  CLIENT_BODY_BUFFER_SIZE)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  CLIENT_BODY_TIMEOUT)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  CLIENT_HEADER_BUFFER_SIZE)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  CLIENT_HEADER_TIMEOUT)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  CLIENT_MAX_BODY_SIZE)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_max_body_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  KEEPALIVE_REQUESTS)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_requests = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  KEEPALIVE_TIMEOUT)
    {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header ==  ACCESSLOG)
		this->_accesslog = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  DEFAULT_TYPE)
		this->_default_type = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  ERRORLOG)
		this->_errorlog = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  ROOT)
		this->_root = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  CGI_PATH)
		this->_cgi_path = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  ALIAS)
		this->_alias = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  UPLOAD_PATH)
		this->_upload_path = HandlingString::obtain_without_ows_value(field_value);
	if (field_header ==  ALLOW_METHODS)
		this->_allow_methods = ConfigHandlingString::ready_string_vector_field_value(field_value);
	if (field_header ==  INDEX)
		this->_index = ConfigHandlingString::ready_string_vector_field_value(field_value);
	if (field_header ==  ERRORPAGES)
		this->_errorpages = ConfigHandlingString::ready_string_vector_field_value(field_value);
	if (field_header ==  SERVER_NAME)
		this->_server_name = ConfigHandlingString::ready_string_vector_field_value(field_value);
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

void LocationConfig::init_location_config_with_server_config(const ServerConfig &other)
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
