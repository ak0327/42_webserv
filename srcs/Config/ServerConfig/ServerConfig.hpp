#ifndef SRCS_CONFIG_SERVERCONFIG_SERVERCONFIG_HPP_
#define	SRCS_CONFIG_SERVERCONFIG_SERVERCONFIG_HPP_

#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <iostream>
#include <sstream>
#include "../HandlingString/HandlingString.hpp"
#include "../NumericHandle/NumericHandle.hpp"
#include "../ConfigHandlingString/ConfigHandlingString.hpp"

class ServerConfig
{
	private:
		bool									_autoindex;
		bool									_chunked_transferencoding_allow;
		// ErrorPage 								_errorpage;  // これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
		int										_server_tokens;
		size_t									_client_body_buffer_size;
		size_t									_client_body_timeout;
		size_t									_client_header_buffer_size;
		size_t									_client_header_timeout;
		size_t									_client_maxbody_size;
		size_t									_keepaliverequests;
		size_t									_keepalive_timeout;
		size_t 									_maxBodySize;
		// std::map<std::string, LocationConfig>	_locations;
		std::string								_accesslog;
		std::string								_default_type;
		std::string								_errorlog;
		std::string								_port;
		std::string								_root;
		std::vector<std::string>				_allowmethod_set;
		std::vector<std::string>				_indexpage_set;
		std::vector<std::string>				_server_name;
		// function
		bool									ready_boolean_fieldvalue(const std::string &field_value);
		int										ready_int_fieldvalue(const std::string &field_value);
		size_t									ready_size_t_fieldvalue(const std::string &field_value);
		std::string								ready_string_fieldvalue(const std::string &field_value);
		std::vector<std::string>				ready_string_vector_fieldvalue(const std::string &field_value);
	public:
		ServerConfig();
		ServerConfig(const ServerConfig &other);
		ServerConfig& operator=(const ServerConfig &other);
		~ServerConfig();
		// getter
		bool									get_autoindex();
		bool									get_chunked_transferencoding_allow();
		// ErrorPage 							get_errorpage;
		int										get_server_tokens();
		size_t									get_client_body_buffer_size();
		size_t									get_client_body_timeout();
		size_t									get_client_header_buffer_size();
		size_t									get_client_header_timeout();
		size_t									get_client_maxbody_size();
		size_t									get_keepaliverequests();
		size_t									get_keepalive_timeout();
		size_t 									get_maxBodySize();
		// std::map<std::string, LocationConfig>get	_locations;
		std::string								get_accesslog();
		std::string								get_default_type();
		std::string								get_errorlog();
		std::string								get_port();
		std::string								get_root();
		std::vector<std::string>				get_allowmethod_set();
		std::vector<std::string>				get_indexpage_set();
		std::vector<std::string>				get_server_name();
		// setter
		void									set_autoindex(const bool &boolean);
		void									set_chunked_transferencoding_allow(const bool &boolean);
		// void									set_errorpage;
		void									set_server_tokens(const int &value);
		void									set_client_body_buffer_size(const size_t &client_body_buffer_size);
		void									set_client_body_timeout(const size_t &client_body_timeout);
		void									set_client_header_buffer_size(const size_t &client_header_buffer_size);
		void									set_client_header_timeout(const size_t &client_header_timeout);
		void									set_client_maxbody_size(const size_t &client_maxbody_size);
		void									set_keepaliverequests(const size_t &keepaliverequests);
		void									set_keepalive_timeout(const size_t &keepalive_timeout);
		void									set_maxBodySize(const size_t &max_bodysize);
		// void					 				set_locations();
		void									set_accesslog(const std::string &access_log);
		void									set_default_type(const std::string &default_type);
		void									set_errorlog(const std::string &error_log);
		void									set_port(const std::string &port);
		void									set_root(const std::string &root);
		void									set_allowmethod_set(const std::vector<std::string> &allow_method_set);
		void									set_indexpage_set(const std::vector<std::string> &indexpag_set);
		void									set_server_name(const std::vector<std::string> &indexpage_set);
		// 関数
		bool									ready_serverblock_keyword(const std::string &fiels_key, const std::string &field_value);
		void									clear_serverconfig();
};

#endif  // SRCS_CONFIG_SERVERCONFIG_SERVERCONFIG_HPP_
