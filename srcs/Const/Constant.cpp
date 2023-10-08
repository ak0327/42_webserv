#include <string>
#include "Constant.hpp"

const int OK = 0;
const int NG = 1;

const int STATUS_OK = 200;
const int STATUS_BAD_REQUEST = 400;
const int STATUS_SERVER_ERROR = 500;


const char DECIMAL_POINT = '.';
const char SIGN_PLUS = '+';
const char SIGN_MINUS = '-';

const char CR = '\r';
const char HT = '\t';
const char LF = '\n';
const char SP = ' ';

const char CRLF[] = "\r\n";

const char DELIMITERS[] = "\"(),/:;<=>?@[\\]{}";

const char GET_METHOD[] = "GET";
const char POST_METHOD[] = "POST";
const char DELETE_METHOD[] = "DELETE";

const char HTTP_1_1[] = "HTTP/1.1";
const char HTTP_2_0[] = "HTTP/2.0";
const char HTTP_3_0[] = "HTTP/3.0";

const std::vector<std::string> METHODS = init_methods();
const std::vector<std::string> HTTP_VERSIONS = init_http_versions();

std::vector<std::string> init_methods() {
	std::vector<std::string> methods;

	methods.push_back(std::string(GET_METHOD));
	methods.push_back(std::string(POST_METHOD));
	methods.push_back(std::string(DELETE_METHOD));
	return methods;
}

std::vector<std::string> init_http_versions() {
	std::vector<std::string> http_versions;

	http_versions.push_back(std::string(HTTP_1_1));
	http_versions.push_back(std::string(HTTP_2_0));
	http_versions.push_back(std::string(HTTP_3_0));
	return http_versions;
}
