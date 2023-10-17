#include <algorithm>
#include <string>
#include <map>
#include "../StatusText/StatusText.hpp"

class HttpResponse
{
	private:
		int									_status_code;
		std::string							_response;
		std::map<std::string, StatusText>	_status_text_map;
		void								make_response(const std::string &status_code);
		bool								is_request_over_maxsize(const std::string &request_text, const size_t &maxsize);
		bool								is_header_over_maxsize(const std::string &header_text, const size_t &maxsize);
		bool								is_body_over_maxsize(const std::string &header_text, const size_t &maxsize);
		bool								is_method_allowed(const std::vector<std::string> &allowed_method, const std::string &target);
		void								ready_status_text_map(void);
		std::string							ready_now_time(void) const;
	public:
		HttpResponse();
		~HttpResponse();
}