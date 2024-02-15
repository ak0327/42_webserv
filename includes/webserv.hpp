#pragma once

# include <string>

// Mock -> gmock ??
////////////////////////////////////////////////
# include "HttpRequest.hpp"
# define TEST_RESPONSE_MSG	"test response"

// mock
class HttpResponse {
 public:
	std::string response_message_;

    HttpResponse() {}
	explicit HttpResponse(const HttpRequest &request) {
		int status = request.get_status_code();
		std::string message;

		if (status == STATUS_BAD_REQUEST) {
			message = "400 BAD REQUEST";
		} else if (status == STATUS_SERVER_ERROR) {
			message = "500 SERVER ERROR";
		} else {
			message = "200 OK";
		}
		response_message_ = message;
	}

	std::string get_response_message() const { return response_message_; }
	std::size_t get_response_size() const { return response_message_.size(); }
};
////////////////////////////////////////////////
