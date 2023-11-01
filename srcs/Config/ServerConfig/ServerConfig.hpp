#pragma once

#include <algorithm>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "ConfigHandlingString.hpp"
#include "HandlingString.hpp"
#include "NumericHandle.hpp"

#define AUTOINDEX "autoindex"
#define CHUNKED_TRANSFERENCODING_ALLOW "chunked_transferencoding_allow"
#define SERVER_TOKENS "server_tokens"
#define CLIENT_BODY_BUFFER_SIZE "client_body_buffer_size"
#define CLIENT_BODY_TIMEOUT "client_body_timeout"
#define CLIENT_HEADER_BUFFER_SIZE "client_header_buffer_size"
#define CLIENT_HEADER_TIMEOUT "client_header_timeout"
#define KEEPALIVE_REQUESTS "keepalive_requests"
#define KEEPALIVE_TIMEOUT "keepalive_timeout"
#define CLIENT_MAX_BODY_SIZE "client_max_body_size"
#define ACCESSLOG "accesslog"
#define CGI_EXTENSIONS "cgi_extension"
#define DEFAULT_TYPE "default_type"
#define ERRORLOG "errorlog"
#define LISTEN "listen"
#define PORT "port"
#define ROOT "root"
#define ALLOW_METHODS "allow_methods"
#define INDEX "index"
#define SERVER_NAME "server_name"

class ServerConfig
{
	private:
		bool									_autoindex;
		bool									_chunked_transferencoding_allow;
		int										_server_tokens;
		size_t									_client_body_buffer_size;
		size_t									_client_body_timeout;
		size_t									_client_header_buffer_size;
		size_t									_client_header_timeout;
		size_t									_keepalive_requests;
		size_t									_keepalive_timeout;
		size_t 									_client_max_body_size;
		std::string								_accesslog;
		std::string								_cgi_extension;
		std::string								_default_type;
		std::string								_errorlog;
		std::string								_port;
		std::string								_root;
		std::vector<std::string>				_allow_methods;
		std::vector<std::string>				_index;
		std::vector<std::string>				_server_name;
		void	init_server_config();
	public:
		ServerConfig();
		ServerConfig(const ServerConfig &other);
		ServerConfig& operator=(const ServerConfig &other);
		~ServerConfig();

		// getter
		bool									get_autoindex() const;
		bool									get_chunked_transferencoding_allow() const;
		int										get_server_tokens() const;
		size_t									get_client_body_buffer_size() const;
		size_t									get_client_body_timeout() const;
		size_t									get_client_header_buffer_size() const;
		size_t									get_client_header_timeout() const;
		size_t									get_keepalive_requests() const;
		size_t									get_keepalive_timeout() const;
		size_t 									get_client_max_body_size() const;
		std::string								get_accesslog() const;
		std::string								get_default_type() const;
		std::string								get_errorlog() const;
		std::string								get_port() const;
		std::string								get_root() const;
		std::vector<std::string>				get_allow_methods() const;
		std::vector<std::string>				get_index() const;
		std::vector<std::string>				get_server_name() const;
		// setter
		void									set_autoindex(const bool &boolean);
		void									set_chunked_transferencoding_allow(const bool &boolean);
		void									set_server_tokens(const int &value);
		void									set_client_body_buffer_size(const size_t &client_body_buffer_size);
		void									set_client_body_timeout(const size_t &client_body_timeout);
		void									set_client_header_buffer_size(const size_t &client_header_buffer_size);
		void									set_client_header_timeout(const size_t &client_header_timeout);
		void									set_keepalive_requests(const size_t &keepaliverequests);
		void									set_keepalive_timeout(const size_t &keepalive_timeout);
		void									set_client_max_body_size(const size_t &max_bodysize);
		void									set_accesslog(const std::string &access_log);
		void									set_default_type(const std::string &default_type);
		void									set_errorlog(const std::string &error_log);
		void									set_port(const std::string &port);
		void									set_root(const std::string &root);
		void									set_allow_methods(const std::vector<std::string> &allow_methods);
		void									set_index(const std::vector<std::string> &indexpags);
		void									set_server_name(const std::vector<std::string> &indexpages);
		bool									set_field_header_field_value(const std::string &field_header, const std::string &field_value);
		void									clear_serverconfig();
};
