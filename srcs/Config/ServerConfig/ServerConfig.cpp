#include "ServerConfig.hpp"

ServerConfig::ServerConfig(): _autoindex(false), _chunked_transferencoding_allow(false), _server_tokens(1),
_client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024),
_client_header_timeout(60), _keepalive_requests(0), _keepalive_timeout(0), _client_max_body_size(1024),
_default_type("application/octet-stream"){}

ServerConfig::ServerConfig(const ServerConfig &other)
{
	this->_autoindex =	other._autoindex;
	this->_chunked_transferencoding_allow =	other._chunked_transferencoding_allow;
	// this->// _errorpage;  // これめっちゃおかしい使い方 =	other->// _errorpage;  // これめっちゃおかしい使い方で
	this->_server_tokens =	other._server_tokens;
	this->_client_body_buffer_size = other._client_body_buffer_size;
	this->_client_body_timeout = other._client_body_timeout;
	this->_client_header_buffer_size =	other._client_header_buffer_size;
	this->_client_header_timeout =	other._client_header_timeout;
	this->_keepalive_requests =	other._keepalive_requests;
	this->_keepalive_timeout =	other._keepalive_timeout;
	this->_client_max_body_size =	other._client_max_body_size;
	// this->// _locations =	other->// _locations;
	this->_accesslog =	other._accesslog;
	this->_default_type =	other._default_type;
	this->_errorlog =	other._errorlog;
	this->_port =	other._port;
	this->_root =	other._root;
	this->_allow_methods = other._allow_methods;
	this->_index = other._index;
	this->_server_name = other._server_name;
}

ServerConfig& ServerConfig::operator=(const ServerConfig &other)
{
    if (this == &other)
	{
        return *this;
	}
	this->_autoindex =	other._autoindex;
	this->_chunked_transferencoding_allow =	other._chunked_transferencoding_allow;
	// this->// _errorpage;  // これめっちゃおかしい使い方 =	other->// _errorpage;  // これめっちゃおかしい使い方で
	this->_server_tokens =	other._server_tokens;
	this->_client_body_buffer_size = other._client_body_buffer_size;
	this->_client_body_timeout = other._client_body_timeout;
	this->_client_header_buffer_size =	other._client_header_buffer_size;
	this->_client_header_timeout =	other._client_header_timeout;
	this->_keepalive_requests =	other._keepalive_requests;
	this->_keepalive_timeout =	other._keepalive_timeout;
	this->_client_max_body_size =	other._client_max_body_size;
	// this->// _locations =	other->// _locations;
	this->_accesslog =	other._accesslog;
	this->_default_type =	other._default_type;
	this->_errorlog =	other._errorlog;
	this->_port =	other._port;
	this->_root =	other._root;
	this->_allow_methods = other._allow_methods;
	this->_index = other._index;
	this->_server_name = other._server_name;
    return *this;
}

ServerConfig::~ServerConfig(){}

bool ServerConfig::ready_boolean_field_value(const std::string &field_value)
{
	if (field_value == "on")
		return (true);
	return (false);
}

int ServerConfig::ready_int_field_value(const std::string &field_value){ return (NumericHandle::str_to_int(field_value)); }

size_t ServerConfig::ready_size_t_field_value(const std::string &field_value){ return (static_cast<size_t>(NumericHandle::str_to_int(field_value))); }

std::string ServerConfig::ready_string_field_value(const std::string &field_value){ return (field_value); }

std::vector<std::string> ServerConfig::ready_string_vector_field_value(const std::string &field_value)
{
	std::vector<std::string>	anser_vector;
	std::istringstream			values_splited_by_empty(field_value);
	std::string					value_splited_by_empty;
	size_t	value_start_pos = 0;
	size_t	value_end_pos = 0;

	while (field_value[value_start_pos] != '\0')
	{
		HandlingString::skip_no_ows(field_value, &value_end_pos);
		anser_vector.push_back(field_value.substr(value_start_pos, value_end_pos - value_start_pos));
		HandlingString::skip_ows(field_value, &value_end_pos);
		value_start_pos = value_end_pos;
	}
	return (anser_vector);
}

bool	ServerConfig::set_field_header_field_value(const std::string &field_header, \
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
	field_headers.push_back("cgi_extension");
	field_headers.push_back("default_type");
	field_headers.push_back("errorlog");
	field_headers.push_back("port");
	field_headers.push_back("root");
	field_headers.push_back("allow_methods");
	field_headers.push_back("index");
	field_headers.push_back("server_name");
	field_headers.push_back("listen");

	if (std::find(field_headers.begin(), field_headers.end(), field_header) == field_headers.end())
	{
		std::cout << "NO EXIST FIELD KEY" << std::endl;
		return false;
	}
	if (field_header == "autoindex")
	{
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_autoindex = this->ready_boolean_field_value(field_value);
	}
	if (field_header == "chunked_transferencoding_allow")
	{
		if (!(field_value == "on" || field_value == "off"))
			return false;
		this->_chunked_transferencoding_allow = this->ready_boolean_field_value(field_value);
	}
	if (field_header == "server_tokens")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_server_tokens = this->ready_int_field_value(field_value);
	}
	if (field_header == "client_body_buffer_size")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_buffer_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "client_body_timeout")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_body_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "client_header_buffer_size")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_buffer_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "client_header_timeout")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_header_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "client_max_body_size")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_client_max_body_size = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "keepalive_requests")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_requests = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "keepalive_timeout")
	{
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_keepalive_timeout = this->ready_size_t_field_value(field_value);
	}
	if (field_header == "accesslog")
		this->_accesslog = this->ready_string_field_value(field_value);
	if (field_header == "cgi_extension")
		this->_cgi_extension = this->ready_string_field_value(field_value);
	if (field_header == "default_type")
		this->_default_type = this->ready_string_field_value(field_value);
	if (field_header == "listen")
		this->_port = this->ready_string_field_value(HandlingString::obtain_without_ows_value(field_value));
	if (field_header == "errorlog")
		this->_errorlog = this->ready_string_field_value(HandlingString::obtain_without_ows_value(field_value));
	if (field_header == "port")
	{
		// requestないと照合する際はstring型で扱いそうなので意図的にstd::string型にしている
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value)))
			return false;
		this->_port = this->ready_string_field_value(HandlingString::obtain_without_ows_value(field_value));
	}
	if (field_header == "root")
		this->_root = this->ready_string_field_value(HandlingString::obtain_without_ows_value(field_value));
	if (field_header == "allow_methods")
		this->_allow_methods = this->ready_string_vector_field_value(field_value);
	if (field_header == "index")
		this->_index = this->ready_string_vector_field_value(field_value);
	if (field_header == "server_name")
		this->_server_name = this->ready_string_vector_field_value(field_value);
	return (true);
}

void	ServerConfig::set_autoindex(const bool &boolean){ this->_autoindex = boolean; }
void	ServerConfig::set_chunked_transferencoding_allow(const bool &boolean){ this->_chunked_transferencoding_allow = boolean; }
// void	ServerConfig::set_errorpage;  // これめっちゃおか
void	ServerConfig::set_server_tokens(const int &server_tokens){ this->_server_tokens = server_tokens; }
void	ServerConfig::set_client_body_buffer_size(const size_t &client_body_buffer_size){ this->_client_body_buffer_size = client_body_buffer_size; }
void	ServerConfig::set_client_body_timeout(const size_t &client_body_timeout){ this->_client_body_timeout = client_body_timeout; }
void	ServerConfig::set_client_header_buffer_size(const size_t &client_header_buffer_size)
{
	this->_client_header_buffer_size = client_header_buffer_size;
}
void	ServerConfig::set_client_header_timeout(const size_t &client_header_timeout) { this->_client_body_timeout = client_header_timeout; }
void	ServerConfig::set_keepalive_requests(const size_t &keepaliverequests){ this->_keepalive_requests = keepaliverequests; }
void	ServerConfig::set_keepalive_timeout(const size_t &keepalive_timeout){ this->_keepalive_timeout = keepalive_timeout; }
void	ServerConfig::set_client_max_body_size(const size_t &client_max_body_size){ this->_client_max_body_size = client_max_body_size; }
// void		ServerConfig::set_locations();
void	ServerConfig::set_accesslog(const std::string &access_log){ this->_accesslog = access_log; }
void	ServerConfig::set_default_type(const std::string &default_type){ this->_default_type = default_type; }
void	ServerConfig::set_errorlog(const std::string &error_log){ this->_errorlog = error_log; }
void	ServerConfig::set_port(const std::string &port){ this->_port = port; }
void	ServerConfig::set_root(const std::string &root){ this->_root = root; }
void	ServerConfig::set_allow_methods(const std::vector<std::string> &allow_methods){ this->_allow_methods = allow_methods; }
void	ServerConfig::set_index(const std::vector<std::string> &index){ this->_index = index; }
void	ServerConfig::set_server_name(const std::vector<std::string> &server_name){ this->_server_name = server_name; }

bool	ServerConfig::get_autoindex() const { return (this->_autoindex); }
bool	ServerConfig::get_chunked_transferencoding_allow() const { return (this->_chunked_transferencoding_allow); }
// ErrorPage 							get_errorpage;  // これめっちゃおか
int		ServerConfig::get_server_tokens() const { return (this->_server_tokens); }
size_t	ServerConfig::get_client_body_buffer_size() const { return (this->_client_body_buffer_size); }
size_t	ServerConfig::get_client_body_timeout() const { return (this->_client_body_timeout); }
size_t	ServerConfig::get_client_header_buffer_size() const { return (this->_client_header_buffer_size); }
size_t	ServerConfig::get_client_header_timeout() const { return (this->_client_header_timeout); }
size_t	ServerConfig::get_keepalive_requests() const { return (this->_keepalive_requests); }
size_t	ServerConfig::get_keepalive_timeout() const { return (this->_keepalive_timeout); }
size_t 	ServerConfig::get_client_max_body_size() const { return (this->_client_max_body_size); }
// std::map<std::string, LocationConfig>get	_locations;
std::string	ServerConfig::get_accesslog() const { return (this->_accesslog); }
std::string	ServerConfig::get_default_type() const { return (this->_default_type); }
std::string	ServerConfig::get_errorlog() const { return (this->_errorlog); }
std::string	ServerConfig::get_port() const { return (this->_port); }
std::string	ServerConfig::get_root() const { return (this->_root); }
std::vector<std::string>	ServerConfig::get_allow_methods() const { return (this->_allow_methods); }
std::vector<std::string>	ServerConfig::get_index() const { return (this->_index); }
std::vector<std::string>	ServerConfig::get_server_name() const { return (this->_server_name); }

// autoindex(false)
// _chunked_transferencoding_allow(false)
// _server_tokens(1)
// _client_body_buffer_size(8000)
// _client_body_timeout(60)
// _client_header_buffer_size(1024)
// _client_header_timeout(60)
// _client_maxbody_size(1048576)
// _keepalive_requests(0)
// _keepalive_timeout(0)
// _maxBodySize(1024)
// _default_type("application/octet-stream")
void	ServerConfig::clear_serverconfig()
{
	this->set_autoindex(false);
	this->set_chunked_transferencoding_allow(false);
	this->set_server_tokens(1);
	this->set_client_body_buffer_size(8000);
	this->set_client_header_timeout(60);
	this->set_keepalive_requests(0);
	this->set_keepalive_timeout(0);
	this->set_client_max_body_size(1024);
	this->set_accesslog("");
	this->set_default_type("");
	this->set_default_type("application/octet-stream");
	this->set_errorlog("");
	this->set_port("");
	this->set_root("");
	this->_allow_methods.clear();
	this->_index.clear();
}
