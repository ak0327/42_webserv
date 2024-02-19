#include <sstream>
#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "HttpResponse.hpp"

TEST(HttpResponseGet, AutoIndexGetDirectoryListening) {
	std::string request_target = "autoindex_files";
	HttpRequest request("GET", request_target);
	Config config;
	config.set_autoindex(true);

	HttpResponse response(request, config);

	// now: just print for check body
	std::cerr << CYAN << response.get_response_message() << RESET << std::endl;
}
