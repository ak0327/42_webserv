#pragma once

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include "ErrorPage.hpp"
#include "LocationConfig.hpp"
#include "HandlingString.hpp"

class ErrorPage;
class LocationConfig;

class ServerConfig
{
 private:
		std::string								_port;
		std::vector<std::string>				_server_name;
		std::string								_root;
		std::vector<std::string>				_indexpage_set;
		std::vector<std::string>				_allowmethod_set;
		size_t 									_maxBodySize;
		ErrorPage 								_errorpage;  // これめっちゃおかしい使い方できる　error_page 403 404 500 503 =404 /custom_404.html;
		bool									_chunked_transferencoding_allow;
		std::string								_accesslog;
		std::string								_errorlog;
		size_t									_keepaliverequests;
		size_t									_keepalive_timeout;
		int										_server_tokens;
		bool									_autoindex;
		size_t									_client_body_buffer_size;
		size_t									_client_body_timeout;
		size_t									_client_header_buffer_size;
		size_t									_client_header_timeout;
		size_t									_client_maxbody_size;
		std::string								_default_type;

		std::map<std::string, LocationConfig>	_locations;  // locationディレクティブに関して

 public:
		ServerConfig();
		~ServerConfig();
		// ServerConfig& operator=(const ServerConfig& other);
		// ServerConfig& operator=(ServerConfig& other);

		bool									serverkeyword_insert(std::string const &line, size_t pos);
		bool									serverkeyword_ch(const std::string& word);
		void									show_serverconfig_allinfo();
		void									value_check();

		// void									reset_contents();

		void									set_port(std::string const &port){ this->_port = port; }
		void									set_servername(std::vector<std::string> const &server_name)
		{ 
			if (server_name.empty() == true)
				std::cout << "this is no contents" << std::endl;
			else
				std::cout << "this is contents" << std::endl;
			this->_server_name = server_name;
			if (this->_server_name.empty() == true)
				std::cout << "this is no contents" << std::endl;
			else
				std::cout << "this is contents" << std::endl;
		}
		void									set_root(std::string const &root){ this->_root = root; }
		void									set_indexpage_set(std::vector<std::string> const &index_page){ this->_indexpage_set = index_page; }
		void									set_allowmethod_set(std::vector<std::string> const &allowed_methods){ this->_allowmethod_set = allowed_methods; }
		void									set_locations(std::string &key, LocationConfig &locationconf);
		void									set_maxBodySize(size_t const &max_bodysize) { this->_maxBodySize = max_bodysize; }
		// void									set_errorpage_set(error_page const &error_page) { this->_errorpage = error_page; }
		void									set_chunked_transferencoding_allow(bool const &allow_or_not) { this->_chunked_transferencoding_allow = allow_or_not; }
		void									set_accesslog(std::string const &access_log) { this->_accesslog = access_log; }
		void									set_errorlog(std::string const &error_log) { this->_errorlog = error_log; }
		void									set_keepaliverequests(size_t const &max_requests) { this->_keepaliverequests = max_requests; }
		void									set_keepalive_timeout(size_t const &timeout) { this->_keepalive_timeout = timeout; }
		void									set_autoindex(bool const &on_off) {this->_autoindex = on_off; }
		void									set_client_body_buffer_size(size_t const &buffersize) { this->_client_body_buffer_size = buffersize; }
		void									set_client_body_timeout(size_t const &timeout) { this->_client_body_timeout = timeout; }
		void									set_client_header_buffer_size(size_t const &buffersize) { this->_client_header_buffer_size = buffersize; }
		void									set_client_header_timeout(size_t const &timeout) { this->_client_header_timeout = timeout; }
		void									set_client_maxbody_size(size_t const &buffersize) { this->_client_maxbody_size = buffersize; }
		void									set_default_type(std::string const &default_type) { this->_default_type = default_type; }

		std::string								get_port(void) const { return (this->_port); }
		std::vector<std::string>				get_servername(void) const { return (this->_server_name); }
		std::string								get_root(void) const { return (this->_root); }
		std::vector<std::string>				get_indexpage_set(void) const { return (this->_indexpage_set); }
		std::vector<std::string>				get_allowmethod_set(void) const { return (this->_allowmethod_set); }
		std::map<std::string, LocationConfig>	get_locations(void) const { return (this->_locations); }
		// std::map<int, std::string>				get_location_rank(void) const;
		size_t									get_maxBodySize(void) const { return (this->_maxBodySize); }
		// error_page								get_errorpage_set(void) const { return (this->_errorpage); }
		bool									get_chunked_transferencoding_allow(void) const { return (this->_chunked_transferencoding_allow); }
		std::string								get_accesslog(void) const { return (this->_accesslog); }
		std::string								get_errorlog(void) const { return (this->_errorlog); }
		size_t									get_keepaliverequests(void) const { return (this->_keepaliverequests); }
		size_t									get_keepalive_timeout(void) const { return (this->_keepalive_timeout); }
		bool									get_autoindex(void) const { return (this->_autoindex); }
		size_t									get_client_body_buffer_size(void) const { return (this->_client_body_buffer_size); }
		size_t									get_client_body_timeout(void) const { return (this->_client_body_timeout); }
		size_t									get_client_header_buffer_size(void) const { return (this->_client_header_buffer_size); }
		size_t									get_client_header_timeout(void) const { return (this->_client_header_timeout); }
		size_t									get_client_maxbody_size(void) const { return (this->_client_maxbody_size); }
		std::string								get_default_type(void) const { return (this->_default_type); }
		int										get_version(void) const {return (this->_server_tokens); }

		class	ConfigSyntaxError  // snakecaseにのっとる？
		{
			public:  // NOLINT
				ConfigSyntaxError(const std::string& error_keyword, size_t line): _keyword(error_keyword), _line(line) {}
				virtual const char* what() const throw()
				{
					std::string error_message = "This is Config Syntax Error\nerror keyword is -> " + _keyword + "\nline is -> " + HandlingString::int_to_str(_line);
					char *error_message_ptr = new char[error_message.size() + 1];
					std::strcpy(error_message_ptr, error_message.c_str());
					return error_message_ptr;
				};
			private:  // NOLINT
				std::string	_keyword;
				size_t		_line;
		};

		class	ServerKeywordError
		{
			public:  // NOLINT
				ServerKeywordError(const std::string& error_keyword, size_t line): _keyword(error_keyword), _line(line) {}
				virtual const char* what() const throw()
				{
					std::string error_message = "This is Keyword Error\nerror keyword is -> " + _keyword + "\nline is -> " + HandlingString::int_to_str(_line);
					char *error_message_ptr = new char[error_message.size() + 1];
					std::strcpy(error_message_ptr, error_message.c_str());
					return error_message_ptr;
				};
			private:  // NOLINT
				std::string	_keyword;
				size_t		_line;
		};

		class	ConfigServerdhirecthiveError  // snakecaseにのっとる？　クラスここまで必要かな
		{
			public:  // NOLINT
				virtual const char* what() const throw() { return "This is Config Server Dhirecthive Error";}
		};

		class	ConfigLocationdhirecthiveError  // snakecaseにのっとる？
		{
			public:  // NOLINT
				virtual const char* what() const throw() { return "This is Config Location Dhirecthive Error";}
		};
};