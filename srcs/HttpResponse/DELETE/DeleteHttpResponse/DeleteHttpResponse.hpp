#ifndef SRCS_HTTPRESPONSE_DELETE_DELETEHTTPRESPONSE_DELETEHTTPRESPONSE_HPP_
#define SRCS_HTTPRESPONSE_DELETE_DELETEHTTPRESPONSE_DELETEHTTPRESPONSE_HPP_

#include <time.h>
#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "../StatusText/StatusText.hpp"

class DeleteHttpResponse
{
	private:
		int	_status_code;
		std::string	_response;
		std::map<std::string, StatusText>	_status_text_map;

		void make_response(const std::string &status_code);
		void ready_status_text_map(void);

		bool is_authority_form(const std::string &target_uri);
		bool is_asterisk_form(const std::string &target_uri);
		bool is_authority(const std::string &request_path);
		bool is_body_under_maxsize(const std::string &header_text, const size_t &maxsize);
		bool is_header_under_maxsize(const std::string &header_text, const size_t &maxsize);
		bool is_method_allowed(const std::vector<std::string> &allowed_method, const std::string &target);
		bool is_origin_form(const std::string &target_uri);
		bool is_request_under_maxsize(const std::string &request_text, const size_t &maxsize);

		std::string	ready_now_time(void) const;
		std::string	skip_authority(const std::string &target_path);
		std::string	trim_query(const std::string &target_uri);
		std::string	trim_scheme_and_query(const std::string &target_uri);
	public:
		DeleteHttpResponse();
		~DeleteHttpResponse();
		std::string	get_location_from_requestline_targeturi(const std::string &target_uri);
		std::string	get_location_path(const std::string &requested_path);
};

#endif  // SRCS_HTTPRESPONSE_DELETE_DELETEHTTPRESPONSE_DELETEHTTPRESPONSE_HPP_
