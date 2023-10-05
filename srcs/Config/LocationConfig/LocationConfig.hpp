#ifndef LOCATIONINFS_HPP
#define	LOCATIONINFS_HPP

#include "../HandlingString/HandlingString.hpp"
#include "../NumericHandle/NumericHandle.hpp"
#include "../ConfigHandlingString/ConfigHandlingString.hpp"

#include <string>
#include <sstream>
#include <iostream>
#include <vector>

class LocationConfig
{
	private:
		bool									_autoindex;
		bool									_chunked_transferencoding_allow;
		int										_server_tokens;
		size_t									_client_body_buffer_size;
		size_t									_client_body_timeout;
		size_t									_client_header_buffer_size;
		size_t									_client_header_timeout;
		size_t									_client_max_body_size;
		size_t									_keepaliverequests;
		size_t									_keepalive_timeout;
		size_t 									_maxBodySize;
		std::string								_alias;
		// error_page						 		_errorpage_set;//これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
		std::string								_accesslog;
		std::string								_cgi_path;
		std::string								_default_type;
		std::string								_errorlog;
		std::string								_upload_path;
		std::string								_root;
		std::vector<std::string>				_allowmethod_set;
		std::vector<std::string>				_indexpage_set;
		std::vector<std::string>				_server_name;
		std::vector<std::string>				_errorpage_set;
		// function
		bool									ready_boolean_fieldvalue(const std::string &field_value);
		int										ready_int_fieldvalue(const std::string &field_value);
		size_t									ready_size_t_fieldvalue(const std::string &field_value);
		std::string								ready_string_fieldvalue(const std::string &field_value);
		std::vector<std::string>				ready_string_vector_fieldvalue(const std::string &field_value);
	public:
		LocationConfig();
		~LocationConfig();
		bool									get_autoindex(void);
		bool									get_chunked_transferencoding_allow(void);
		int										get_server_tokens(void);
		size_t									get_client_body_buffer_size(void);
		size_t									get_client_body_timeout(void);
		size_t									get_client_header_buffer_size(void);
		size_t									get_client_header_timeout(void);
		size_t									get_client_max_body_size(void);
		size_t									get_keepaliverequests(void);
		size_t									get_keepalive_timeout(void);
		size_t 									get_maxBodySize(void);
		std::string								get_alias(void);
		// error_page						 	get	_errorpage_set;//これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
		std::string								get_accesslog(void);
		std::string								get_cgi_path(void);
		std::string								get_default_type(void);
		std::string								get_errorlog(void);
		std::string								get_upload_path(void);
		std::string								get_root(void);
		std::vector<std::string>				get_allowmethod_set(void);
		std::vector<std::string>				get_indexpage_set(void);
		std::vector<std::string>				get_server_name(void);
		std::vector<std::string>				get_errorpage_set(void);
		bool									ready_locationblock_keyword(const std::string &field_key, const std::string &field_value);
};

#endif
