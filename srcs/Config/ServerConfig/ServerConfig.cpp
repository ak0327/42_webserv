#include "LocationConfig.hpp"
#include "ServerConfig.hpp"

ServerConfig::ServerConfig():_autoindex(false), _chunked_transferencoding_allow(false),
_server_tokens(1), _client_body_buffer_size(8000), _client_body_timeout(60), _client_header_buffer_size(1024), _client_header_timeout(60), _client_maxbody_size(1048576), _keepaliverequests(0), _keepalive_timeout(0), _maxBodySize(1024), _default_type("application/octet-stream")
{

}

ServerConfig::~ServerConfig(){}

bool ServerConfig::serverkeyword_ch(const std::string& word)
{
	const std::string server_keyset_arr[] = {
        "listen", "server_name", "root", "index", "allow_methods", "error_page", "types", "cgi_extension",
        "chunked_transfer_encoding", "access_log", "error_log", "keepalive_requests",
        "keepalive_timeout", "server_tokens", "autoindex", "rewrite", "return", "client_body_buffer_size",
        "client_body_timeout", "client_header_buffer_size", "client_header_timeout",
        "client_max_body_size", "default_type"
    };

    const std::set<std::string> server_keyset
    (
        server_keyset_arr,
        server_keyset_arr + sizeof(server_keyset_arr) / sizeof(server_keyset_arr[0])
    );  // NOLINT

    if (server_keyset.count(word) > 0)
        return true;
    return false;
}

bool	ServerConfig::serverkeyword_insert(std::string const &line, size_t pos)
{
	std::istringstream	splited_woeds(line);
	std::string			key_word;
	std::string			val;
	std::string			val_two;

	splited_woeds >> key_word >> val_two;
	val = HandlingString::skip_lastsemicolon(val_two);
	if (this->serverkeyword_ch(key_word) == false)
		throw ServerConfig::ServerKeywordError(key_word, pos);
	if (key_word == "listen")
		this->set_port(val);
	else if (key_word == "cgi_extension")  // 何するかわかってない
		;
	else if (key_word == "server_name")
		this->set_servername(HandlingString::input_arg_to_vector_without_firstword(line));
	else if (key_word == "root")
		this->set_root(val);
	else if (key_word == "index")
		this->set_indexpage_set(HandlingString::input_arg_to_vector_without_firstword(line));
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
	else
		return (false);
	return (true);
}

void ServerConfig::set_locations(std::string &key, LocationConfig &locationconf){ _locations[key] = locationconf; }
