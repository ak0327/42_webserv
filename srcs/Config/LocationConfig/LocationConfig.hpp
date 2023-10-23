#ifndef SRCS_CONFIG_LOCATIONCONFIG_LOCATIONCONFIG_HPP_
#define	SRCS_CONFIG_LOCATIONCONFIG_LOCATIONCONFIG_HPP_

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "../ConfigHandlingString/ConfigHandlingString.hpp"
#include "../HandlingString/HandlingString.hpp"
#include "../NumericHandle/NumericHandle.hpp"
#include "../ServerConfig/ServerConfig.hpp"

class LocationConfig
{
	private:
		bool						_autoindex;
		bool						_chunked_transferencoding_allow;
		int							_server_tokens;
		size_t						_client_body_buffer_size;
		size_t						_client_body_timeout;
		size_t						_client_header_buffer_size;
		size_t						_client_header_timeout;
		size_t						_client_max_body_size;
		size_t						_keepalive_requests;
		size_t						_keepalive_timeout;
		std::string					_alias;
		std::string					_accesslog;
		std::string					_cgi_path;
		std::string					_default_type;
		std::string					_errorlog;
		std::string					_upload_path;
		std::string					_root;
		std::vector<std::string>	_allow_methods;
		std::vector<std::string>	_index;
		std::vector<std::string>	_server_name;
		std::vector<std::string>	_errorpages;
		// function
		bool						ready_boolean_field_value(const std::string &field_value);
		int							ready_int_field_value(const std::string &field_value);
		size_t						ready_size_t_field_value(const std::string &field_value);
		std::vector<std::string>	ready_string_vector_field_value(const std::string &field_value);
	public:
		LocationConfig();
		~LocationConfig();
		bool						get_autoindex(void);
		bool						get_chunked_transferencoding_allow(void);
		int							get_server_tokens(void);
		size_t						get_client_body_buffer_size(void);
		size_t						get_client_body_timeout(void);
		size_t						get_client_header_buffer_size(void);
		size_t						get_client_header_timeout(void);
		size_t						get_client_max_body_size(void);
		size_t						get_keepalive_requests(void);
		size_t						get_keepalive_timeout(void);
		std::string					get_alias(void);
		std::string					get_accesslog(void);
		std::string					get_cgi_path(void);
		std::string					get_default_type(void);
		std::string					get_errorlog(void);
		std::string					get_upload_path(void);
		std::string					get_root(void);
		std::vector<std::string>	get_allow_methods(void);
		std::vector<std::string>	get_index(void);
		std::vector<std::string>	get_server_name(void);
		std::vector<std::string>	get_errorpages(void);  // 修正したい
		void						set_autoindex(const bool &autoindex){ this->_autoindex = autoindex; }
		void						set_chunked_transferencoding_allow(const bool &chunked_transferencoding_allow)
		{
			this->_chunked_transferencoding_allow = chunked_transferencoding_allow;
		}
		void						set_server_tokens(const int &server_tokens){ this->_server_tokens = server_tokens; }
		void						set_client_body_buffer_size(const size_t &client_body_buffer_size){ this->_client_body_buffer_size = client_body_buffer_size; }
		void						set_client_body_timeout(const size_t &client_body_timeout){ this->_client_body_timeout = client_body_timeout; }
		void						set_client_header_buffer_size(const size_t &client_header_buffer_size){ this->_client_header_buffer_size = client_header_buffer_size; }
		void						set_client_header_timeout(const size_t &client_header_timeout){ this->_client_header_timeout = client_header_timeout; }
		void						set_client_max_body_size(const size_t &client_max_body_size){ this->_client_max_body_size = client_max_body_size; }
		void						set_keepaliverequests(const size_t &keepalive_request){ this->_keepalive_requests = keepalive_request; }
		void						set_keepalive_timeout(const size_t &keepalive_timeout){ this->_keepalive_timeout = keepalive_timeout; }
		void						set_maxBodySize(const size_t &client_max_body_size){ this->_client_max_body_size = client_max_body_size; }
		void						set_alias(const std::string &alias){ this->_alias = alias;  }
		void						set_accesslog(const std::string &accesslog){ this->_accesslog = accesslog; }
		void						set_cgi_path(const std::string &cgi_path){ this->_cgi_path = cgi_path; }
		void						set_default_type(const std::string &default_type){ this->_default_type = default_type; }
		void						set_errorlog(const std::string &errorlog){ this->_errorlog = errorlog; }
		void						set_upload_path(const std::string &upload_path){ this->_upload_path = upload_path; }
		void						set_root(const std::string &root){ this->_root = root; }
		void						set_allow_methods(const std::vector<std::string> &allow_methods){ this->_allow_methods = allow_methods; }
		void						set_index(const std::vector<std::string> &index){ this->_index = index; }
		void						set_server_name(const std::vector<std::string> &server_name){ this->_server_name = server_name; }
		void						set_errorpages(const std::vector<std::string> &errorpages){ this->_errorpages = errorpages; }
		bool						set_field_header_field_value(const std::string &field_header, \
																const std::string &field_value);
		void						clear_location_keyword(void);
		void						set_server_block_infs(const ServerConfig &inputes_severconfig);
};

#endif  // SRCS_CONFIG_LOCATIONCONFIG_LOCATIONCONFIG_HPP_
