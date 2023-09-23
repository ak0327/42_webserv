#include "LocationConfig.hpp"
#include "ServerConfig.hpp"
#include "../HandlingString/ConfigHandlingString.hpp"

LocationConfig::LocationConfig():_maxBodySize(1024), _chunked_transferencoding_allow(false),
_keepaliverequests(10), _server_tokens(1), _autoindex(false), _default_type("application/octet-stream")
{

}

LocationConfig::LocationConfig(ServerConfig const &some):_maxBodySize(1024), _chunked_transferencoding_allow(false),
_keepaliverequests(10), _server_tokens(1), _autoindex(false), _default_type("application/octet-stream")
{
	this->_port = some.get_port();
	this->_server_name = some.get_servername();
	this->_root = some.get_root();
	this->_indexpage_set = some.get_indexpage_set();
	this->_allowmethod_set = some.get_allowmethod_set();
	this->_maxBodySize = some.get_maxBodySize();
	// this->_errorpage_set = some.get_errorpage_set();
	this->_chunked_transferencoding_allow = some.get_chunked_transferencoding_allow();
	this->_accesslog = some.get_accesslog();
	this->_errorlog = some.get_errorlog();
	this->_keepaliverequests = some.get_keepaliverequests();
	this->_keepalive_timeout = some.get_keepalive_timeout();
	this->_autoindex = some.get_autoindex();
	this->_client_body_buffer_size = some.get_client_body_buffer_size();
	this->_client_body_timeout = some.get_client_body_timeout();
	this->_client_header_buffer_size = some.get_client_body_buffer_size();
	this->_client_header_timeout = some.get_client_header_timeout();
	this->_client_maxbody_size = some.get_client_maxbody_size();
	this->_default_type = some.get_default_type();
}

LocationConfig& LocationConfig::operator=(const LocationConfig& some) {
    if (this != &some)
	{
        this->_port = some.get_port();
		this->_server_name = some.get_servername();
		this->_root = some.get_root();
		this->_indexpage_set = some.get_indexpage_set();
		this->_allowmethod_set = some.get_allowmethod_set();
		this->_maxBodySize = some.get_maxBodySize();
		// this->_errorpage_set = some.get_errorpage_set();
		// this->_chunked_transferencoding_allow = some.get_chunked_transferencoding_allow();
		// this->_accesslog = some.get_accesslog();
		// this->_errorlog = some.get_errorlog();
		// this->_keepaliverequests = some.get_keepaliverequests();
		// this->_keepalive_timeout = some.get_keepalive_timeout();
		// this->_autoindex = some.get_autoindex();
		// this->_client_body_buffer_size = some.get_client_body_buffer_size();
		// this->_client_body_timeout = some.get_client_body_timeout();
		// this->_client_header_buffer_size = some.get_client_body_buffer_size();
		// this->_client_header_timeout = some.get_client_header_timeout();
		// this->_client_maxbody_size = some.get_client_maxbody_size();
		// this->_default_type = some.get_default_type();
    }
    return *this;
}

LocationConfig& LocationConfig::operator=(LocationConfig& some) {
    if (this != &some)
	{
        this->_port = some.get_port();
		this->_server_name = some.get_servername();
		this->_root = some.get_root();
		this->_indexpage_set = some.get_indexpage_set();
		this->_allowmethod_set = some.get_allowmethod_set();
		this->_maxBodySize = some.get_maxBodySize();
		// this->_errorpage_set = some.get_errorpage_set();
		// this->_chunked_transferencoding_allow = some.get_chunked_transferencoding_allow();
		// this->_accesslog = some.get_accesslog();
		// this->_errorlog = some.get_errorlog();
		// this->_keepaliverequests = some.get_keepaliverequests();
		// this->_keepalive_timeout = some.get_keepalive_timeout();
		// this->_autoindex = some.get_autoindex();
		// this->_client_body_buffer_size = some.get_client_body_buffer_size();
		// this->_client_body_timeout = some.get_client_body_timeout();
		// this->_client_header_buffer_size = some.get_client_body_buffer_size();
		// this->_client_header_timeout = some.get_client_header_timeout();
		// this->_client_maxbody_size = some.get_client_maxbody_size();
		// this->_default_type = some.get_default_type();
    }
    return *this;
}

LocationConfig::~LocationConfig()
{
	
}

void LocationConfig::reset_locationconf()
{
	this->_port = "";
	this->_server_name.clear();
	this->_root.clear();
	this->_alias = "";
	this->_indexpage_set.clear();
	this->_allowmethod_set.clear();
	this->_maxBodySize = 0;
	// std::memset(&this->_errorpage_set, 0, sizeof(this->_errorpage_set));
	this->_chunked_transferencoding_allow = true;
	this->_accesslog = "";
	this->_errorlog = "";
	this->_keepaliverequests = 10;
	this->_keepalive_timeout = 60;
	this->_server_tokens = 1.0;
	this->_autoindex = false;
	this->_client_body_buffer_size = 1024;
	this->_client_body_timeout = 60;
	this->_client_header_buffer_size = 1024;
	this->_client_header_timeout = 60;
	this->_client_maxbody_size = 1024;
	this->_default_type = "text/plain";
	this->_cgi_path = "";
	this->_upload_path = "";
}

void LocationConfig::reset_locationconf(ServerConfig const &some)
{
	this->_port = some.get_port();
	this->_server_name = some.get_servername();
	this->_root = some.get_root();
	this->_indexpage_set = some.get_indexpage_set();
	this->_allowmethod_set = some.get_allowmethod_set();
	this->_maxBodySize = some.get_maxBodySize();
	// this->_errorpage_set = some.get_errorpage_set();
	this->_chunked_transferencoding_allow = some.get_chunked_transferencoding_allow();
	this->_accesslog = some.get_accesslog();
	this->_errorlog = some.get_errorlog();
	this->_keepaliverequests = some.get_keepaliverequests();
	this->_keepalive_timeout = some.get_keepalive_timeout();
	this->_autoindex = some.get_autoindex();
	this->_client_body_buffer_size = some.get_client_body_buffer_size();
	this->_client_body_timeout = some.get_client_body_timeout();
	this->_client_header_buffer_size = some.get_client_body_buffer_size();
	this->_client_header_timeout = some.get_client_header_timeout();
	this->_client_maxbody_size = some.get_client_maxbody_size();
	this->_default_type = some.get_default_type();

	_cgi_path = "";
	_upload_path = "";
}

void	LocationConfig::show_locationconfinf()
{
	std::cout << "============" << std::endl;
	std::cout << "port is " << this->get_port() << std::endl;
	if (this->get_servername().size() != 0)
		std::cout << "servername is " << this->get_servername()[0] << std::endl;
	std::cout << "             " << std::endl;
	std::cout << "root is " << this->get_root() << std::endl;
	std::cout << "alias is " << this->get_alias() << std::endl;
	std::cout << "             " << std::endl;
	if (this->get_autoindex() == true)
		std::cout << "autoindex is true" << std::endl;
	else
		std::cout << "autoindex is false" << std::endl;
	std::cout << "             " << std::endl;
	std::cout << "cgi_path is " << this->get_cgi_path() << std::endl;
	std::cout << "             " << std::endl;
}

bool	LocationConfig::locationkeyword_ch(std::string const &key_word)
{
	const std::string server_keyset_arr[] = {
        "root", "index", "error_page", "areas", "allow_methods",
		"chunked_transfer_encoding", "access_log", "error_log", "keepalive_requests",
		"keepalive_timeout", "server_tokens", "autoindex", "rewrite", "return", "client_body_buffer_size",
		"client_body_timeout", "client_header_buffer_size", "client_header_timeout",
		"client_max_body_size", "default_type", "log_not_found", "cgi_path", "alias", "upload_path"
    };

    const std::set<std::string> location_keyset
    (
        server_keyset_arr,
        server_keyset_arr + sizeof(server_keyset_arr) / sizeof(server_keyset_arr[0])
    );

    if (location_keyset.count(key_word) > 0)
        return true;
    return false;
}

bool	LocationConfig::insert_location(std::string const &line)
{
	std::istringstream	splited_woeds(line);
	std::string			key_word;
	std::string			val_two;
	std::string			val;

	splited_woeds >> key_word >> val_two;
	if (key_word == "" && val == "")
		return (true);
	val = HandlingString::skip_lastsemicolon(val_two);
	if (locationkeyword_ch(key_word) == false)
		return (false);
	if (key_word == "listen")
		this->set_port(val);
	else if (key_word == "cgi_extension")  // 何するかわかってない
		;
	else if (key_word == "server_name")
		this->set_servername(HandlingString::input_arg_to_vector_without_firstword(line));
	else if (key_word == "root")
		this->set_root(val);
	else if (key_word == "alias")
		this->set_alias(val);
	else if (key_word == "index")
		this->set_root(val);
	else if (key_word == "allow_methods")
		this->set_allowmethod_set(HandlingString::input_arg_to_vector_without_firstword(line));
	else if (key_word == "error_page")
		this->set_errorlog(val);
	else if (key_word == "chunked_transfer_encoding")
	{
		if (val != "on" && val != "off")
			return (false);
		if (val == "on")
			this->set_chunked_transferencoding_allow(true);
		else
			this->set_chunked_transferencoding_allow(false);
	}
	else if (key_word == "access_log")
		this->set_accesslog(val);
	else if (key_word == "error_log")
		this->set_errorlog(val);
	else if (key_word == "keepalive_requests")
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_keepaliverequests(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "keepalive_timeout")  // timeoutの実装がC++98のみでは難しい、Cでも許可された関数にない
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_keepalive_timeout(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "server_tokens")
		;
	else if (key_word == "autoindex")
	{
		if (val != "on" && val != "off")
			return (false);
		if (val == "on")
			this->set_autoindex(true);
		else
			this->set_autoindex(false);
	}
	else if (key_word == "upload_path")
		this->set_upload_path(val);
	else if (key_word == "rewrite")  // 何するのかわからん
		;
	else if (key_word == "return")  // 何するのかわからん
		;
	else if (key_word == "client_body_buffer_size")  // 単位付きで入ってくる場合に対応する必要性、簡単のために単位なしに一旦する
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_client_body_buffer_size(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "client_body_timeout")
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_client_body_timeout(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "client_header_buffer_size")
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_client_header_buffer_size(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "client_header_timeout")
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_client_header_timeout(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "client_max_body_size")
	{
		if (HandlingString::is_positive_and_under_intmax(val) == false)
			return (false);
		this->set_client_maxbody_size(HandlingString::str_to_int(HandlingString::skip_lastsemicolon(val)));
	}
	else if (key_word == "default_type")
		this->set_default_type(val);
	else if (key_word == "cgi_path")
		this->set_cgi_path(val);
	else if (key_word == "allow_methods")
		this->set_allowmethod_set(HandlingString::input_arg_to_vector_without_firstword(line));
	else
		return (false);
	// return (true);
	return (true);
}

// 　-＝ ∧ ∧　　setterだよ！　∧ ∧ ＝-
// -＝と( ･∀･)			   （･∀･ ) ＝-
// 　-＝/ と_ノ			     と_ノヾ ＝-
// -＝_/／⌒ｿ				   (_＞､＼ ＝-

void	LocationConfig::set_port(std::string const &port){ this->_port = port; }
void	LocationConfig::set_servername(std::vector<std::string> const &server_name){ this->_server_name = server_name; }
void	LocationConfig::set_root(std::string const &root){ this->_root = root; }
void	LocationConfig::set_indexpage_set(std::vector<std::string> const &_indexpage_set){ this->_indexpage_set = _indexpage_set; }
void	LocationConfig::set_allowmethod_set(std::vector<std::string> const &_allowed_method){ this->_allowmethod_set = _allowed_method; }
void	LocationConfig::set_maxBodySize(size_t const &maxBodySize){ this->_maxBodySize = maxBodySize; }
// void	LocationConfig::set_errorpage_set(error_page const &errorpage_set){ this->_errorpage_set = errorpage_set; }
void	LocationConfig::set_chunked_transferencoding_allow(bool const &allow_or_not){ this->_chunked_transferencoding_allow = allow_or_not; }
void	LocationConfig::set_accesslog(std::string const &access_log){ this->_accesslog = access_log; }
void	LocationConfig::set_errorlog(std::string const &error_log){ this->_errorlog = error_log; }
void	LocationConfig::set_keepaliverequests(size_t const &max_requests){ this->_keepaliverequests = max_requests; }
void	LocationConfig::set_keepalive_timeout(size_t const &timeout){ this->_keepalive_timeout = timeout; }
void	LocationConfig::set_autoindex(bool const &on_off){ this->_autoindex = on_off; }
void	LocationConfig::set_client_body_buffer_size(size_t const &buffersize){ this->_client_body_buffer_size = buffersize; }
void	LocationConfig::set_client_body_timeout(size_t const &timeout){ this->_client_body_timeout = timeout; }
void	LocationConfig::set_client_header_buffer_size(size_t const &buffersize){ this->_client_header_buffer_size = buffersize; }
void	LocationConfig::set_client_header_timeout(size_t const &timeout){ this->_client_header_timeout = timeout; }
void	LocationConfig::set_client_maxbody_size(size_t const &buffersize){ this->_client_maxbody_size = buffersize; }
void	LocationConfig::set_default_type(std::string const &default_type){ this->_default_type = default_type; }
void	LocationConfig::set_cgi_path(std::string const &cgi_path){ this->_cgi_path = cgi_path; }
void	LocationConfig::set_alias(std::string const &alias){ this->_alias = alias; }
void	LocationConfig::set_upload_path(std::string const &upload_path){ this->_upload_path = upload_path; }

//     ∩∩     getterだよ
//   （´･ω･）
//   ＿| ⊃／(＿＿_
//  ／ └-(＿＿＿_／
//  ￣￣￣￣￣￣￣

std::string								LocationConfig::get_port(void) const { return (this->_port); }
std::vector<std::string>				LocationConfig::get_servername(void) const { return (this->_server_name); }
std::string								LocationConfig::get_root(void) const {return (this->_root); }
std::vector<std::string>				LocationConfig::get_indexpage_set(void) const { return (this->_indexpage_set); }
std::vector<std::string>				LocationConfig::get_allowmethod_set(void) const { return (this->_allowmethod_set); }
size_t									LocationConfig::get_maxBodySize(void) const { return (this->_maxBodySize); }
// error_page								LocationConfig::get_errorpage_set(void) const { return (this->_errorpage_set); }
bool									LocationConfig::get_chunked_transferencoding_allow(void) { return (this->_chunked_transferencoding_allow); }
std::string								LocationConfig::get_accesslog(void) { return (this->_accesslog); }
std::string								LocationConfig::get_errorlog(void) {return (this->_errorlog); }
size_t									LocationConfig::get_keepaliverequests(void) { return (this->_keepaliverequests); }
size_t									LocationConfig::get_keepalive_timeout(void) { return (this->_keepalive_timeout); }
bool									LocationConfig::get_autoindex(void) { return (this->_autoindex); }
size_t									LocationConfig::get_client_body_buffer_size(void) { return (this->_client_body_buffer_size); }
size_t									LocationConfig::get_client_body_timeout(void) { return (this->_client_body_timeout); }
size_t									LocationConfig::get_client_header_buffer_size(void) { return (this->_client_header_buffer_size); }
size_t									LocationConfig::get_client_header_timeout(void) { return (this->_client_header_timeout); }
size_t									LocationConfig::get_client_maxbody_size(void) { return (this->_maxBodySize); }
std::string								LocationConfig::get_default_type(void) { return (this->_default_type); }
int										LocationConfig::get_version(void) { return (this->_server_tokens); }
std::string								LocationConfig::get_cgi_path(void) { return (this->_cgi_path); }
std::string								LocationConfig::get_alias(void) { return (this->_alias); }
std::string								LocationConfig::get_upload_path(void) { return (this->_upload_path); }
