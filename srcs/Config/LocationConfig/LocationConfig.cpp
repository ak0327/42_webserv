#include "LocationConfig.hpp"

LocationConfig::LocationConfig()
{
	// _autoindex;
	// _chunked_transferencoding_allow;
	// _server_tokens;
	// _client_body_buffer_size;
	// _client_body_timeout;
	// _client_header_buffer_size;
	// _client_header_timeout;
	// _client_maxbody_size;
	// _keepaliverequests;
	// _keepalive_timeout;
	// _maxBodySize;
	// _alias;
	// 	_errorpage_set;//これめっち
	// _accesslog;
	// _cgi_path;
	// _default_type;
	// _errorlog;
	// _upload_path;
	// _port;
	// _root;
	// _allowmethod_set;
	// _indexpage_set;
	// _server_name;
}

LocationConfig::~LocationConfig(){}

void	LocationConfig::ready_locationblock_keyword(const std::string &field_key, const std::string &field_value)
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
	field_keys.push_back("cgi_path");
	field_keys.push_back("alias");
	field_keys.push_back("upload_path");

      std::cout << field_value << std::endl;
	if (std::find(field_keys.begin(), field_keys.end(), field_key) == field_keys.end())
		return;
      if (field_key == "autoindex")
            std::cout << "選択されたのはメニュー 1 です。" << std::endl;
      else if (field_key ==  "chunked_transferencoding_allow")
            std::cout << "選択されたのはメニュー 2 です。" << std::endl;
      else if (field_key ==  "server_tokens")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "client_body_buffer_size")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "client_body_timeout")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "client_header_buffer_size")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "client_header_timeout")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "client_maxbody_size")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "keepaliverequests")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "keepalive_timeout")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "maxBodySize")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "accesslog")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "default_type")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "errorlog")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "port")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "root")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "allowmethod_set")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "indexpage_set")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "server_name")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "cgi_path")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "alias")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
	else if (field_key ==  "upload_path")
            std::cout << "選択されたのはメニュー 3 です。" << std::endl;
}
