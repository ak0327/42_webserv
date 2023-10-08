#pragma once

# include <string>
# include <vector>

extern const int OK;
extern const int NG;

extern const int STATUS_OK;
extern const int STATUS_BAD_REQUEST;
extern const int STATUS_SERVER_ERROR;

extern const char DECIMAL_POINT;
extern const char SIGN_PLUS;
extern const char SIGN_MINUS;

extern const char CR;
extern const char HT;
extern const char LF;
extern const char SP;

extern const char CRLF[];

extern const char DELIMITERS[];

extern const char GET_METHOD[];
extern const char POST_METHOD[];
extern const char DELETE_METHOD[];

extern const char HTTP_1_1[];
extern const char HTTP_2_0[];
extern const char HTTP_3_0[];

extern const std::vector<std::string> METHODS;
extern const std::vector<std::string> HTTP_VERSIONS;

std::vector<std::string> init_methods();
std::vector<std::string> init_http_versions();
