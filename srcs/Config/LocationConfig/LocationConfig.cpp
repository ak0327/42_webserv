#include "LocationConfig.hpp"

LocationConfig::LocationConfig() {
	init_location_keyword();
}

LocationConfig::LocationConfig(const LocationConfig &other)
{
	this->_autoindex = other.get_autoindex();
	this->_chunked_transferencoding_allow = other.get_chunked_transferencoding_allow();
	this->_server_tokens = other.get_server_tokens();
	this->_client_body_buffer_size = other.get_client_body_buffer_size();
	this->_client_body_timeout = other.get_client_body_timeout();
	this->_client_header_buffer_size = other.get_client_header_buffer_size();
	this->_client_header_timeout = other.get_client_header_timeout();
	this->_client_max_body_size = other.get_client_max_body_size();
	this->_keepalive_requests = other.get_keepalive_requests();
	this->_keepalive_timeout = other.get_keepalive_timeout();
	this->_alias = other.get_alias();
	this->_accesslog = other.get_accesslog();
	this->_cgi_path = other.get_cgi_path();
	this->_default_type = other.get_default_type();
	this->_errorlog = other.get_errorlog();
	this->_upload_path = other.get_upload_path();
	this->_root = other.get_root();
	this->_allow_methods = other.get_allow_methods();
	this->_index = other.get_index();
	this->_server_name = other.get_server_name();
	this->_errorpages = other.get_errorpages();
	return (*this);
}

LocationConfig& LocationConfig::operator=(const LocationConfig &other)
{
	if (this == &other)
		return (*this);
	this->_autoindex = other.get_autoindex();
	this->_chunked_transferencoding_allow = other.get_chunked_transferencoding_allow();
	this->_server_tokens = other.get_server_tokens();
	this->_client_body_buffer_size = other.get_client_body_buffer_size();
	this->_client_body_timeout = other.get_client_body_timeout();
	this->_client_header_buffer_size = other.get_client_header_buffer_size();
	this->_client_header_timeout = other.get_client_header_timeout();
	this->_client_max_body_size = other.get_client_max_body_size();
	this->_keepalive_requests = other.get_keepalive_requests();
	this->_keepalive_timeout = other.get_keepalive_timeout();
	this->_alias = other.get_alias();
	this->_accesslog = other.get_accesslog();
	this->_cgi_path = other.get_cgi_path();
	this->_default_type = other.get_default_type();
	this->_errorlog = other.get_errorlog();
	this->_upload_path = other.get_upload_path();
	this->_root = other.get_root();
	this->_allow_methods = other.get_allow_methods();
	this->_index = other.get_index();
	this->_server_name = other.get_server_name();
	this->_errorpages = other.get_errorpages();
	return (*this);
}

LocationConfig::~LocationConfig(){}

bool LocationConfig::set_field_header_field_value(const std::string &field_header,
												  const std::string &field_value)
{
	std::vector<std::string> field_headers;

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

	if (std::find(field_headers.begin(), field_headers.end(), field_header) == field_headers.end()) {
		return false;
	}

    if (field_header == AUTOINDEX)
    {
		if (!(field_value == "on" || field_value == "off")) {
			return false;
		}
		this->_autoindex = ConfigHandlingString::ready_boolean_field_value(field_value);
	} else if (field_header ==  CHUNKED_TRANSFERENCODING_ALLOW) {
		if (!(field_value == "on" || field_value == "off")) {
			return false;
		}
		this->_chunked_transferencoding_allow = ConfigHandlingString::ready_boolean_field_value(field_value);
	} else if (field_header ==  SERVER_TOKENS) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_server_tokens = ConfigHandlingString::ready_int_field_value(field_value);
	} else if (field_header ==  CLIENT_BODY_BUFFER_SIZE) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_client_body_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  CLIENT_BODY_TIMEOUT) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_client_body_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  CLIENT_HEADER_BUFFER_SIZE) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_client_header_buffer_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  CLIENT_HEADER_TIMEOUT) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_client_header_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  CLIENT_MAX_BODY_SIZE) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_client_max_body_size = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  KEEPALIVE_REQUESTS) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_keepalive_requests = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  KEEPALIVE_TIMEOUT) {
		if (!(NumericHandle::is_positive_and_under_intmax_int(field_value))) {
			return false;
		}
		this->_keepalive_timeout = ConfigHandlingString::ready_size_t_field_value(field_value);
	} else if (field_header ==  ACCESSLOG) {
		this->_accesslog = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  DEFAULT_TYPE) {
		this->_default_type = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  ERRORLOG) {
		this->_errorlog = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  ROOT) {
		this->_root = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  CGI_PATH) {
		this->_cgi_path = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  ALIAS) {
		this->_alias = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  UPLOAD_PATH) {
		this->_upload_path = HandlingString::obtain_without_ows_value(field_value);
	} else if (field_header ==  ALLOW_METHODS) {
		this->_allow_methods = ConfigHandlingString::ready_string_vector_field_value(field_value);
	} else if (field_header ==  INDEX) {
		this->_index = ConfigHandlingString::ready_string_vector_field_value(field_value);
	} else if (field_header ==  ERRORPAGES) {
		this->_errorpages = ConfigHandlingString::ready_string_vector_field_value(field_value);
	} else if (field_header ==  SERVER_NAME) {
		this->_server_name = ConfigHandlingString::ready_string_vector_field_value(field_value);
	}
	return (true);
}

bool	LocationConfig::get_autoindex() const { return (this->_autoindex); }
bool	LocationConfig::get_chunked_transferencoding_allow() const { return (this->_chunked_transferencoding_allow); }
int		LocationConfig::get_server_tokens() const { return (this->_server_tokens); }
size_t	LocationConfig::get_client_body_buffer_size() const { return (this->_client_body_buffer_size); }
size_t	LocationConfig::get_client_body_timeout() const { return (this->_client_body_timeout); }
size_t	LocationConfig::get_client_header_buffer_size() const { return (this->_client_header_buffer_size); }
size_t	LocationConfig::get_client_header_timeout() const { return (this->_client_header_timeout); }
size_t	LocationConfig::get_client_max_body_size() const { return (this->_client_max_body_size); }
size_t	LocationConfig::get_keepalive_requests() const { return (this->_keepalive_requests); }
size_t	LocationConfig::get_keepalive_timeout() const { return (this->_keepalive_timeout); }
std::string	LocationConfig::get_alias() const { return (this->_alias); }
// error_page		LocationConfig::get	_errorpage_set;//これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
std::string	LocationConfig::get_accesslog() const { return (this->_accesslog); }
std::string	LocationConfig::get_cgi_path() const { return (this->_cgi_path); }
std::string	LocationConfig::get_default_type() const { return (this->_default_type); }
std::string	LocationConfig::get_errorlog() const { return (this->_errorlog); }
std::string	LocationConfig::get_upload_path() const { return (this->_upload_path); }
std::string	LocationConfig::get_root() const { return (this->_root); }
std::vector<std::string> LocationConfig::get_allow_methods() const { return (this->_allow_methods); }
std::vector<std::string> LocationConfig::get_index() const { return (this->_index); }
std::vector<std::string> LocationConfig::get_server_name() const { return (this->_server_name); }
std::vector<std::string> LocationConfig::get_errorpages() const { return (this->_errorpages); }

void LocationConfig::set_autoindex(const bool &autoindex) { this->_autoindex = autoindex; }
void LocationConfig::set_chunked_transferencoding_allow(const bool &chunked_transferencoding_allow)
{
	this->_chunked_transferencoding_allow = chunked_transferencoding_allow;
}
void LocationConfig::set_server_tokens(const int &server_tokens) { this->_server_tokens = server_tokens; }
void LocationConfig::set_client_body_buffer_size(const size_t &client_body_buffer_size) {
	this->_client_body_buffer_size = client_body_buffer_size;
}

void LocationConfig::set_client_body_timeout(const size_t &client_body_timeout) {
	this->_client_body_timeout = client_body_timeout;
}

void LocationConfig::set_client_header_buffer_size(const size_t &client_header_buffer_size) {
	this->_client_header_buffer_size = client_header_buffer_size;
}

void LocationConfig::set_client_header_timeout(const size_t &client_header_timeout) {
	this->_client_header_timeout = client_header_timeout;
}

void LocationConfig::set_client_max_body_size(const size_t &client_max_body_size) {
	this->_client_max_body_size = client_max_body_size;
}

void LocationConfig::set_keepaliverequests(const size_t &keepalive_request) { this->_keepalive_requests = keepalive_request; }
void LocationConfig::set_keepalive_timeout(const size_t &keepalive_timeout) { this->_keepalive_timeout = keepalive_timeout; }
void LocationConfig::set_maxBodySize(const size_t &client_max_body_size) { this->_client_max_body_size = client_max_body_size; }
void LocationConfig::set_alias(const std::string &alias) { this->_alias = alias;  }
void LocationConfig::set_accesslog(const std::string &accesslog) { this->_accesslog = accesslog; }
void LocationConfig::set_cgi_path(const std::string &cgi_path) { this->_cgi_path = cgi_path; }
void LocationConfig::set_default_type(const std::string &default_type) { this->_default_type = default_type; }
void LocationConfig::set_errorlog(const std::string &errorlog) { this->_errorlog = errorlog; }
void LocationConfig::set_upload_path(const std::string &upload_path) { this->_upload_path = upload_path; }
void LocationConfig::set_root(const std::string &root) { this->_root = root; }
void LocationConfig::set_allow_methods(const std::vector<std::string> &allow_methods) { this->_allow_methods = allow_methods; }
void LocationConfig::set_index(const std::vector<std::string> &index) { this->_index = index; }
void LocationConfig::set_server_name(const std::vector<std::string> &server_name) { this->_server_name = server_name; }
void LocationConfig::set_errorpages(const std::vector<std::string> &errorpages) { this->_errorpages = errorpages; }

void LocationConfig::init_location_keyword()
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

// todo: implement ConfigDetail Class, use copy assignment constructor
void LocationConfig::init_location_config_with_server_config(const ServerConfig &server_config)
{
	this->set_autoindex(server_config.get_autoindex());
	this->set_chunked_transferencoding_allow(server_config.get_chunked_transferencoding_allow());
	this->set_server_tokens(server_config.get_server_tokens());
	this->set_client_body_buffer_size(server_config.get_client_body_buffer_size());
	this->set_client_header_timeout(server_config.get_client_header_timeout());
	this->set_client_max_body_size(server_config.get_client_max_body_size());
	this->set_keepaliverequests(server_config.get_keepalive_requests());
	this->set_keepalive_timeout(server_config.get_keepalive_timeout());
	this->set_accesslog(server_config.get_accesslog());
	this->set_default_type(server_config.get_default_type());
	this->set_default_type(server_config.get_default_type());
	this->set_errorlog(server_config.get_errorlog());
	this->set_root(server_config.get_root());
	this->set_allow_methods(server_config.get_allow_methods());
	this->_index.clear();
}
