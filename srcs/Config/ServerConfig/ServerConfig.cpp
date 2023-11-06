#include "ServerConfig.hpp"
#include "Config.hpp"

ServerConfig::ServerConfig()
{
	init_server_config();
}

ServerConfig::ServerConfig(const ServerConfig &other)
{
	*this = other;
}

ServerConfig& ServerConfig::operator=(const ServerConfig &other)
{
    if (this == &other)
	{
        return *this;
	}
	this->_autoindex =	other._autoindex;
	this->_chunked_transferencoding_allow =	other._chunked_transferencoding_allow;
	this->_server_tokens = other._server_tokens;
	this->_client_body_buffer_size = other._client_body_buffer_size;
	this->_client_body_timeout = other._client_body_timeout;
	this->_client_header_buffer_size = other._client_header_buffer_size;
	this->_client_header_timeout = other._client_header_timeout;
	this->_keepalive_requests =	other._keepalive_requests;
	this->_keepalive_timeout = other._keepalive_timeout;
	this->_client_max_body_size = other._client_max_body_size;
	this->_accesslog = other._accesslog;
	this->_default_type = other._default_type;
	this->_errorlog = other._errorlog;
	this->_cgi_extension = other._cgi_extension;
	this->_port = other._port;
	this->_root = other._root;
	this->_allow_methods = other._allow_methods;
	this->_index = other._index;
	this->_server_name = other._server_name;
    return *this;
}

ServerConfig::~ServerConfig() {}

bool	ServerConfig::set_field_header_field_value(const std::string &field_header, \
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
	field_headers.push_back(CGI_EXTENSIONS);
	field_headers.push_back(DEFAULT_TYPE);
	field_headers.push_back(ERRORLOG);
	field_headers.push_back(ROOT);
	field_headers.push_back(ALLOW_METHODS);
	field_headers.push_back(INDEX);
	field_headers.push_back(SERVER_NAME);
	field_headers.push_back(LISTEN);

	if (std::find(field_headers.begin(), field_headers.end(), field_header) == field_headers.end())
	{
		std::cout << "NO EXIST FIELD KEY" << std::endl;
		return false;
	}
	if (field_header == AUTOINDEX)
	{
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_autoindex = ConfigHandlingString::ready_boolean_field_value(field_value);
	}
	if (field_header == CHUNKED_TRANSFERENCODING_ALLOW)
	{
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_chunked_transferencoding_allow = ConfigHandlingString::ready_boolean_field_value(field_value);
	}
	if (field_header == SERVER_TOKENS)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_server_tokens = ConfigHandlingString::ready_int_field_value(field_value);
	}
	if (field_header == CLIENT_BODY_BUFFER_SIZE)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == CLIENT_BODY_TIMEOUT)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == CLIENT_HEADER_BUFFER_SIZE)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == CLIENT_HEADER_TIMEOUT)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == CLIENT_MAX_BODY_SIZE)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_max_body_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == KEEPALIVE_REQUESTS)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_requests = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == KEEPALIVE_TIMEOUT)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == LISTEN)
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_port = ConfigHandlingString::ready_size_t_field_value(field_value);
	}
	if (field_header == ACCESSLOG)
		this->_accesslog = HandlingString::obtain_without_ows_value(field_value);
	if (field_header == CGI_EXTENSIONS)
		this->_cgi_extension = HandlingString::obtain_without_ows_value(field_value);
	if (field_header == DEFAULT_TYPE)
		this->_default_type = HandlingString::obtain_without_ows_value(field_value);
	if (field_header == ERRORLOG)
		this->_errorlog = HandlingString::obtain_without_ows_value(field_value);
	if (field_header == ROOT)
		this->_root = HandlingString::obtain_without_ows_value(field_value);
	if (field_header == ALLOW_METHODS)
		this->_allow_methods = ConfigHandlingString::ready_string_vector_field_value(field_value);
	if (field_header == INDEX)
		this->_index = ConfigHandlingString::ready_string_vector_field_value(field_value);
	if (field_header == SERVER_NAME)
		this->_server_name = ConfigHandlingString::ready_string_vector_field_value(field_value);
	return (true);
}

void ServerConfig::set_autoindex(const bool &boolean) { this->_autoindex = boolean; }
void ServerConfig::set_chunked_transferencoding_allow(const bool &boolean) { this->_chunked_transferencoding_allow = boolean; }
void ServerConfig::set_server_tokens(const int &server_tokens) { this->_server_tokens = server_tokens; }
void ServerConfig::set_client_body_buffer_size(const size_t &client_body_buffer_size) { this->_client_body_buffer_size = client_body_buffer_size; }
void ServerConfig::set_client_body_timeout(const size_t &client_body_timeout) { this->_client_body_timeout = client_body_timeout; }
void ServerConfig::set_client_header_buffer_size(const size_t &client_header_buffer_size)
{
	this->_client_header_buffer_size = client_header_buffer_size;
}
void ServerConfig::set_client_header_timeout(const size_t &client_header_timeout) { this->_client_body_timeout = client_header_timeout; }
void ServerConfig::set_keepalive_requests(const size_t &keepalive_requests) { this->_keepalive_requests = keepalive_requests; }
void ServerConfig::set_keepalive_timeout(const size_t &keepalive_timeout) { this->_keepalive_timeout = keepalive_timeout; }
void ServerConfig::set_client_max_body_size(const size_t &max_body_size) { this->_client_max_body_size = max_body_size; }
void ServerConfig::set_port(const size_t &port) { this->_port = port; }

void ServerConfig::set_accesslog(const std::string &access_log) { this->_accesslog = access_log; }
void ServerConfig::set_default_type(const std::string &default_type) { this->_default_type = default_type; }
void ServerConfig::set_errorlog(const std::string &error_log) { this->_errorlog = error_log; }
void ServerConfig::set_root(const std::string &root) { this->_root = root; }
void ServerConfig::set_allow_methods(const std::vector<std::string> &allow_methods) { this->_allow_methods = allow_methods; }
void ServerConfig::set_index(const std::vector<std::string> &index) { this->_index = index; }
void ServerConfig::set_server_name(const std::vector<std::string> &server_name) { this->_server_name = server_name; }

bool ServerConfig::get_autoindex() const { return (this->_autoindex); }
bool ServerConfig::get_chunked_transferencoding_allow() const { return (this->_chunked_transferencoding_allow); }

int ServerConfig::get_server_tokens() const { return (this->_server_tokens); }

size_t ServerConfig::get_client_body_buffer_size() const { return (this->_client_body_buffer_size); }
size_t ServerConfig::get_client_body_timeout() const { return (this->_client_body_timeout); }
size_t ServerConfig::get_client_header_buffer_size() const { return (this->_client_header_buffer_size); }
size_t ServerConfig::get_client_header_timeout() const { return (this->_client_header_timeout); }
size_t ServerConfig::get_keepalive_requests() const { return (this->_keepalive_requests); }
size_t ServerConfig::get_keepalive_timeout() const { return (this->_keepalive_timeout); }
size_t ServerConfig::get_client_max_body_size() const { return (this->_client_max_body_size); }
size_t ServerConfig::get_port() const { return (this->_port); }

std::string	ServerConfig::get_accesslog() const { return (this->_accesslog); }
std::string	ServerConfig::get_cgi_extension() const { return (this->_cgi_extension); }
std::string	ServerConfig::get_default_type() const { return (this->_default_type); }
std::string	ServerConfig::get_errorlog() const { return (this->_errorlog); }
std::string	ServerConfig::get_root() const { return (this->_root); }
std::vector<std::string> ServerConfig::get_allow_methods() const { return (this->_allow_methods); }
std::vector<std::string> ServerConfig::get_index() const { return (this->_index); }
std::vector<std::string> ServerConfig::get_server_name() const { return (this->_server_name); }

void	ServerConfig::clear_server_config()
{
	init_server_config();
}

void ServerConfig::init_server_config()
{
	this->_autoindex = false;
	this->_chunked_transferencoding_allow = false;

	this->_server_tokens = 1;

	this->_client_body_buffer_size = 8000;
	this->_client_body_timeout = 60;
	this->_client_header_buffer_size = 1024;
	this->_client_header_timeout = 60;
	this->_client_max_body_size = 1024;
	this->_keepalive_requests = 0;
	this->_keepalive_timeout = 0;
	this->_port = 80;

	this->_accesslog = "";
	this->_cgi_extension = "";
	this->_default_type = "application/octet-stream";
	this->_errorlog = "";
	this->_root = "";

	this->_allow_methods.clear();
	this->_index.clear();
	this->_server_name.clear();
}
