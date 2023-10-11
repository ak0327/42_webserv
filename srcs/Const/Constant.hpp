#pragma once

# include <string>
# include <vector>

////////////////////////////////////////////////////////////////////////////////

extern const int OK;
extern const int NG;

////////////////////////////////////////////////////////////////////////////////

extern const int STATUS_OK;
extern const int STATUS_BAD_REQUEST;
extern const int STATUS_SERVER_ERROR;

////////////////////////////////////////////////////////////////////////////////

extern const char DECIMAL_POINT;
extern const char SIGN_PLUS;
extern const char SIGN_MINUS;

extern const char CR;
extern const char HT;
extern const char LF;
extern const char SP;

extern const char CRLF[];

extern const char DELIMITERS[];

////////////////////////////////////////////////////////////////////////////////

extern const char GET_METHOD[];
extern const char POST_METHOD[];
extern const char DELETE_METHOD[];

extern const std::vector<std::string> METHODS;

std::vector<std::string> init_methods();

////////////////////////////////////////////////////////////////////////////////

extern const char HTTP_1_1[];
extern const char HTTP_2_0[];
extern const char HTTP_3_0[];

extern const std::vector<std::string> HTTP_VERSIONS;

std::vector<std::string> init_http_versions();

////////////////////////////////////////////////////////////////////////////////

extern const char ACCEPT[];
extern const char ACCEPT_CH[];
extern const char ACCEPT_CHARSET[];
extern const char ACCEPT_ENCODING[];
extern const char ACCEPT_LANGUAGE[];
extern const char ACCEPT_PATCH[];
extern const char ACCEPT_POST[];
extern const char ACCEPT_RANGES[];
extern const char ACCESS_CONTROL_ALLOW_CREDENTIALS[];
extern const char ACCESS_CONTROL_ALLOW_HEADERS[];
extern const char ACCESS_CONTROL_ALLOW_METHODS[];
extern const char ACCESS_CONTROL_ALLOW_ORIGIN[];
extern const char ACCESS_CONTROL_EXPOSE_HEADERS[];
extern const char ACCESS_CONTROL_MAX_AGE[];
extern const char ACCESS_CONTROL_REQUEST_HEADERS[];
extern const char ACCESS_CONTROL_REQUEST_METHOD[];
extern const char AGE[];
extern const char ALLOW[];
extern const char ALT_SVC[];
extern const char ALT_USED[];
extern const char AUTHORIZATION[];
extern const char CACHE_CONTROL[];
extern const char CLEAR_SITE_DATA[];
extern const char CONNECTION[];
extern const char CONTENT_DISPOSITION[];
extern const char CONTENT_ENCODING[];
extern const char CONTENT_LANGUAGE[];
extern const char CONTENT_LENGTH[];
extern const char CONTENT_LOCATION[];
extern const char CONTENT_RANGE[];
extern const char CONTENT_SECURITY_POLICY[];
extern const char CONTENT_SECURITY_POLICY_REPORT_ONLY[];
extern const char CONTENT_TYPE[];
extern const char COOKIE[];
extern const char CROSS_ORIGIN_EMBEDDER_POLICY[];
extern const char CROSS_ORIGIN_OPENER_POLICY[];
extern const char CROSS_ORIGIN_RESOURCE_POLICY[];
extern const char DATE[];
extern const char ETAG[];
extern const char EXPECT[];
extern const char EXPECT_CT[];
extern const char EXPIRES[];
extern const char FORWARDED[];
extern const char FROM[];
extern const char HOST[];
extern const char IF_MATCH[];
extern const char IF_MODIFIED_SINCE[];
extern const char IF_NONE_MATCH[];
extern const char IF_RANGE[];
extern const char IF_UNMODIFIED_SINCE[];
extern const char KEEP_ALIVE[];
extern const char LAST_MODIFIED[];
extern const char LINK[];
extern const char LOCATION[];
extern const char MAX_FORWARDS[];
extern const char ORIGIN[];
extern const char PERMISSION_POLICY[];
extern const char PROXY_AUTHENTICATE[];
extern const char PROXY_AUTHORIZATION[];
extern const char RANGE[];
extern const char REFERER[];
extern const char RETRY_AFTER[];
extern const char SEC_FETCH_DEST[];
extern const char SEC_FETCH_MODE[];
extern const char SEC_FETCH_SITE[];
extern const char SEC_FETCH_USER[];
extern const char SEC_PURPOSE[];
extern const char SEC_WEBSOCKET_ACCEPT[];
extern const char SERVER[];
extern const char SERVER_TIMING[];
extern const char SERVICE_WORKER_NAVIGATION_PRELOAD[];
extern const char SET_COOKIE[];
extern const char SOURCEMAP[];
extern const char STRICT_TRANSPORT_SECURITY[];
extern const char TE[];
extern const char TIMING_ALLOW_ORIGIN[];
extern const char TRAILER[];
extern const char TRANSFER_ENCODING[];
extern const char UPGRADE[];
extern const char UPGRADE_INSECURE_REQUESTS[];
extern const char USER_AGENT[];
extern const char VARY[];
extern const char VIA[];
extern const char WWW_AUTHENTICATE[];
extern const char X_CUSTOM_HEADER[];
