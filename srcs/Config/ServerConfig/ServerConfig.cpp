#include "ServerConfig.hpp"

ServerConfig::ServerConfig(): _autoindex(false), _chunked_transferencoding_allow(false), _server_tokens(1), _client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024), _client_header_timeout(60), _client_maxbody_size(1048576), _keepaliverequests(0), _keepalive_timeout(0), _maxBodySize(1024), _default_type("application/octet-stream"){}

ServerConfig::~ServerConfig(){}

bool ServerConfig::ready_boolean_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (true);
}

int ServerConfig::ready_int_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (0);
}

size_t ServerConfig::ready_size_t_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return (1);
}

std::string ServerConfig::ready_string_fieldvalue(const std::string &field_value)
{
	std::cout << field_value << std::endl;
	return ("");
}

std::vector<std::string> ServerConfig::ready_string_vector_fieldvalue(const std::string &field_value)
{
	std::vector<std::string>	anser_vector;
	std::cout << field_value << std::endl;
	return (anser_vector);
}

bool	ServerConfig::ready_serverblock_keyword(const std::string &field_key, const std::string &field_value)
{
	std::vector<std::string>	field_keys;

	field_keys.push_back("autoindex");
	field_keys.push_back("chunked_transferencoding_allow");
	field_keys.push_back("server_tokens");
	field_keys.push_back("client_body_buffer_size");
	field_keys.push_back("client_body_timeout");
	field_keys.push_back("client_header_buffer_size");
	field_keys.push_back("client_header_timeout");
	field_keys.push_back("client_maxbody_size");
	field_keys.push_back("keepaliverequests");
	field_keys.push_back("keepalive_timeout");
	field_keys.push_back("maxBodySize");
	field_keys.push_back("accesslog");
	field_keys.push_back("default_type");
	field_keys.push_back("errorlog");
	field_keys.push_back("port");
	field_keys.push_back("root");
	field_keys.push_back("allowmethod_set");
	field_keys.push_back("indexpage_set");
	field_keys.push_back("server_name");

	if (std::find(field_keys.begin(), field_keys.end(), field_key) == field_keys.end())
		return true;
	if (field_key == "autoindex")
	{
		this->_autoindex = this->ready_boolean_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "chunked_transferencoding_allow")
	{
		this->_chunked_transferencoding_allow = this->ready_boolean_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "server_tokens")
	{
		this->_server_tokens = this->ready_int_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "client_body_buffer_size")
	{
		this->_client_body_buffer_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "client_body_timeout")
	{
		this->_client_body_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "client_header_buffer_size")
	{
		this->_client_header_buffer_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "client_header_timeout")
	{
		this->_client_header_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "client_maxbody_size")
	{
		this->_client_maxbody_size = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "keepaliverequests")
	{
		this->_keepaliverequests = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "keepalive_timeout")
	{
		this->_keepalive_timeout = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "maxBodySize")
	{
		this->_maxBodySize = this->ready_size_t_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "accesslog")
	{
		this->_accesslog = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "default_type")
	{
		this->_default_type = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "errorlog")
	{
		this->_errorlog = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "port")
	{
		this->_port = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "root")
	{
		this->_root = this->ready_string_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "allowmethod_set")
	{
		this->_allowmethod_set = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "indexpage_set")
	{
		this->_indexpage_set = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	else if (field_key == "server_name")
	{
		this->_server_name = this->ready_string_vector_fieldvalue(field_value);
		return true;
	}
	return (true);
}

void	ServerConfig::set_autoindex(const bool &boolean){ this->_autoindex = boolean; }
void	ServerConfig::set_chunked_transferencoding_allow(const bool &boolean){ this->_chunked_transferencoding_allow = boolean; }
// void	ServerConfig::set_errorpage;  // これめっちゃおか
void	ServerConfig::set_server_tokens(const int &server_tokens){ this->_server_tokens = server_tokens; }
void	ServerConfig::set_client_body_buffer_size(const size_t &client_body_buffer_size){ this->_client_body_buffer_size = client_body_buffer_size; }
void	ServerConfig::set_client_body_timeout(const size_t &client_body_timeout){ this->_client_body_timeout = client_body_timeout; }
void	ServerConfig::set_client_header_buffer_size(const size_t &client_header_buffer_size) { this->_client_header_buffer_size = client_header_buffer_size; }
void	ServerConfig::set_client_header_timeout(const size_t &client_header_timeout) { this->_client_body_timeout = client_header_timeout; }
void	ServerConfig::set_client_maxbody_size(const size_t &client_maxbody_size){ this->_client_maxbody_size = client_maxbody_size; }
void	ServerConfig::set_keepaliverequests(const size_t &keepaliverequests){ this->_keepaliverequests = keepaliverequests; }
void	ServerConfig::set_keepalive_timeout(const size_t &keepalive_timeout){ this->_keepalive_timeout = keepalive_timeout; }
void	ServerConfig::set_maxBodySize(const size_t &max_bodysize){ this->_maxBodySize = max_bodysize; }
// void		ServerConfig::set_locations();
void	ServerConfig::set_accesslog(const std::string &access_log){ this->_accesslog = access_log; }
void	ServerConfig::set_default_type(const std::string &default_type){ this->_default_type = default_type; }
void	ServerConfig::set_errorlog(const std::string &error_log){ this->_errorlog = error_log; }
void	ServerConfig::set_port(const std::string &port){ this->_port = port; }
void	ServerConfig::set_root(const std::string &root){ this->_root = root; }
void	ServerConfig::set_allowmethod_set(std::vector<std::string> &allow_method_set){ this->_allowmethod_set = allow_method_set; }
void	ServerConfig::set_indexpage_set(std::vector<std::string> &indexpage_set){ this->_indexpage_set = indexpage_set; }
void	ServerConfig::set_server_name(std::vector<std::string> &indexpage_set){ this->_indexpage_set = indexpage_set; }

bool	ServerConfig::get_autoindex(){ return (this->_autoindex); }
bool	ServerConfig::get_chunked_transferencoding_allow(){ return (this->_chunked_transferencoding_allow); }
// ErrorPage 							get_errorpage;  // これめっちゃおか
int		ServerConfig::get_server_tokens(){ return (this->_server_tokens); }
size_t	ServerConfig::get_client_body_buffer_size(){ return (this->_client_body_buffer_size); }
size_t	ServerConfig::get_client_body_timeout(){ return (this->_client_body_timeout); }
size_t	ServerConfig::get_client_header_buffer_size(){ return (this->_client_header_buffer_size); }
size_t	ServerConfig::get_client_header_timeout(){ return (this->_client_header_timeout); }
size_t	ServerConfig::get_client_maxbody_size(){ return (this->_client_maxbody_size); }
size_t	ServerConfig::get_keepaliverequests(){ return (this->_keepaliverequests); }
size_t	ServerConfig::get_keepalive_timeout(){ return (this->_keepalive_timeout); }
size_t 	ServerConfig::get_maxBodySize(){ return (this->_maxBodySize); }
// std::map<std::string, LocationConfig>get	_locations;
std::string	ServerConfig::get_accesslog(){ return (this->_accesslog); }
std::string	ServerConfig::get_default_type(){ return (this->_default_type); }
std::string	ServerConfig::get_errorlog(){ return (this->_errorlog); }
std::string	ServerConfig::get_port(){ return (this->_port); }
std::string	ServerConfig::get_root(){ return (this->_root); }
std::vector<std::string>	ServerConfig::get_allowmethod_set(){ return (this->_allowmethod_set); }
std::vector<std::string>	ServerConfig::get_indexpage_set(){ return (this->_indexpage_set); }
std::vector<std::string>	ServerConfig::get_server_name(){ return (this->_server_name); }

// autoindex(false)
// _chunked_transferencoding_allow(false)
// _server_tokens(1)
// _client_body_buffer_size(8000)
// _client_body_timeout(60)
// _client_header_buffer_size(1024)
// _client_header_timeout(60)
// _client_maxbody_size(1048576)
// _keepaliverequests(0)
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
	this->set_client_maxbody_size(1048576);
	this->set_keepaliverequests(0);
	this->set_keepalive_timeout(0);
	this->set_maxBodySize(1024);
	this->set_accesslog("");
	this->set_default_type("");
	this->set_default_type("application/octet-stream");
	this->set_errorlog("");
	this->set_port("");
	this->set_root("");
	this->_allowmethod_set.clear();
	this->_indexpage_set.clear();
}
