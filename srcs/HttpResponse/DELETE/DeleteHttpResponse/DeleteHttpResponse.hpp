#ifndef SRCS_HTTPRESPONSE_DELETE_HTTPRESPONSE_HTTPRESPONSE_HPP_
#define SRCS_HTTPRESPONSE_DELETE_HTTPRESPONSE_HTTPRESPONSE_HPP_

#include <time.h>
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "../StatusText/StatusText.hpp"

enum ManageStatus
{
	IS_OK,
	IS_NOT_PATH_FORMAT
};

class DeleteHttpResponse
{
	private:
		int	_status_code;
		std::string	_response;
		std::map<std::string, StatusText>	_status_text_map;
		void	make_response(const std::string &status_code);
		bool	is_request_under_maxsize(const std::string &request_text, const size_t &maxsize);
		bool	is_header_under_maxsize(const std::string &header_text, const size_t &maxsize);
		bool	is_body_under_maxsize(const std::string &header_text, const size_t &maxsize);
		bool	is_method_allowed(const std::vector<std::string> &allowed_method, const std::string &target);
		void	ready_status_text_map(void);
		std::string	ready_now_time(void) const;
		std::string	get_location_path(const std::string &requested_path);
	public:

		DeleteHttpResponse();
		~DeleteHttpResponse();
		int	separate_path_folda_file(const std::string &request_path, std::string *search_folda, std::string *search_file);
};

#endif  // SRCS_HTTPRESPONSE_DELETE_HTTPRESPONSE_HTTPRESPONSE_HPP_
