#ifndef LOCATIONINFS_HPP
#define	LOCATIONINFS_HPP

#include <string>
#include <sstream>
#include <iostream>
#include <vector>

class LocationConfig
{
	private:
		// bool									_autoindex;
		// bool									_chunked_transferencoding_allow;
		// int										_server_tokens;
		// size_t									_client_body_buffer_size;
		// size_t									_client_body_timeout;
		// size_t									_client_header_buffer_size;
		// size_t									_client_header_timeout;
		// size_t									_client_maxbody_size;
		// size_t									_keepaliverequests;
		// size_t									_keepalive_timeout;
		// size_t 									_maxBodySize;
		// std::string								_alias;
		// // error_page						 		_errorpage_set;//これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
		// std::string								_accesslog;
		// std::string								_cgi_path;
		// std::string								_default_type;
		// std::string								_errorlog;
		// std::string								_upload_path;
		// std::string								_port;
		// std::string								_root;
		// std::vector<std::string>				_allowmethod_set;
		// std::vector<std::string>				_indexpage_set;
		// std::vector<std::string>				_server_name;
		void									ready_locationblock_keyword(const std::string &field_key, const std::string &field_value);
	public:
		LocationConfig();
		~LocationConfig();
};

#endif
