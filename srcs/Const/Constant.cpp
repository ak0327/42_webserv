#include <string>
#include "Constant.hpp"

////////////////////////////////////////////////////////////////////////////////

const int OK = 0;
const int NG = 1;

////////////////////////////////////////////////////////////////////////////////

const int STATUS_OK = 200;
const int STATUS_BAD_REQUEST = 400;
const int STATUS_SERVER_ERROR = 500;

////////////////////////////////////////////////////////////////////////////////

const char DECIMAL_POINT = '.';
const char SIGN_PLUS = '+';
const char SIGN_MINUS = '-';

const char CR = '\r';
const char HT = '\t';
const char LF = '\n';
const char SP = ' ';

const char CRLF[] = "\r\n";

const char DELIMITERS[] = "\"(),/:;<=>?@[\\]{}";

////////////////////////////////////////////////////////////////////////////////

const char GET_METHOD[] = "GET";
const char POST_METHOD[] = "POST";
const char DELETE_METHOD[] = "DELETE";

const std::vector<std::string> METHODS = init_methods();

std::vector<std::string> init_methods() {
	std::vector<std::string> methods;

	methods.push_back(std::string(GET_METHOD));
	methods.push_back(std::string(POST_METHOD));
	methods.push_back(std::string(DELETE_METHOD));
	return methods;
}

////////////////////////////////////////////////////////////////////////////////

const char HTTP_1_1[] = "HTTP/1.1";
const char HTTP_2_0[] = "HTTP/2.0";
const char HTTP_3_0[] = "HTTP/3.0";

const std::vector<std::string> HTTP_VERSIONS = init_http_versions();

std::vector<std::string> init_http_versions() {
	std::vector<std::string> http_versions;

	http_versions.push_back(std::string(HTTP_1_1));
	http_versions.push_back(std::string(HTTP_2_0));
	http_versions.push_back(std::string(HTTP_3_0));
	return http_versions;
}

////////////////////////////////////////////////////////////////////////////////

const char ACCEPT[] = "accept";
const char ACCEPT_CH[] = "accept-ch";
const char ACCEPT_CHARSET[] = "accept-charset";
const char ACCEPT_ENCODING[] = "accept-encoding";
const char ACCEPT_LANGUAGE[] = "accept-language";
const char ACCEPT_PATCH[] = "accept-patch";
const char ACCEPT_POST[] = "accept-post";
const char ACCEPT_RANGES[] = "accept-ranges";
const char ACCESS_CONTROL_ALLOW_CREDENTIALS[] = "access-control-allow-credentials";
const char ACCESS_CONTROL_ALLOW_HEADERS[] = "access-control-allow-headers";
const char ACCESS_CONTROL_ALLOW_METHODS[] = "access-control-allow-methods";
const char ACCESS_CONTROL_ALLOW_ORIGIN[] = "access-control-allow-origin";
const char ACCESS_CONTROL_EXPOSE_HEADERS[] = "access-control-expose-headers";
const char ACCESS_CONTROL_MAX_AGE[] = "access-control-max-age";
const char ACCESS_CONTROL_REQUEST_HEADERS[] = "access-control-request-headers";
const char ACCESS_CONTROL_REQUEST_METHOD[] = "access-control-request-method";
const char AGE[] = "age";
const char ALLOW[] = "allow";
const char ALT_SVC[] = "alt-svc";
const char ALT_USED[] = "alt-used";
const char AUTHORIZATION[] = "authorization";
const char CACHE_CONTROL[] = "cache-control";
const char CLEAR_SITE_DATA[] = "clear-site-data";
const char CONNECTION[] = "connection";
const char CONTENT_DISPOSITION[] = "content-disposition";
const char CONTENT_ENCODING[] = "content-encoding";
const char CONTENT_LANGUAGE[] = "content-language";
const char CONTENT_LENGTH[] = "content-length";
const char CONTENT_LOCATION[] = "content-location";
const char CONTENT_RANGE[] = "content-range";
const char CONTENT_SECURITY_POLICY[] = "content-security-policy";
const char CONTENT_SECURITY_POLICY_REPORT_ONLY[] = "content-security-policy-report-only";
const char CONTENT_TYPE[] = "content-type";
const char COOKIE[] = "cookie";
const char CROSS_ORIGIN_EMBEDDER_POLICY[] = "cross-origin-embedder-policy";
const char CROSS_ORIGIN_OPENER_POLICY[] = "cross-origin-opener-policy";
const char CROSS_ORIGIN_RESOURCE_POLICY[] = "cross-origin-resource-policy";
const char DATE[] = "date";
const char ETAG[] = "etag";
const char EXPECT[] = "expect";
const char EXPECT_CT[] = "expect-ct";
const char EXPIRES[] = "expires";
const char FORWARDED[] = "forwarded";
const char FROM[] = "from";
const char HOST[] = "host";
const char IF_MATCH[] = "if-match";
const char IF_MODIFIED_SINCE[] = "if-modified-since";
const char IF_NONE_MATCH[] = "if-none-match";
const char IF_RANGE[] = "if-range";
const char IF_UNMODIFIED_SINCE[] = "if-unmodified-since";
const char KEEP_ALIVE[] = "keep-alive";
const char LAST_MODIFIED[] = "last-modified";
const char LINK[] = "link";
const char LOCATION[] = "location";
const char MAX_FORWARDS[] = "max-forwards";
const char ORIGIN[] = "origin";
const char PERMISSION_POLICY[] = "permission-policy";
const char PROXY_AUTHENTICATE[] = "proxy-authenticate";
const char PROXY_AUTHORIZATION[] = "proxy-authorization";
const char RANGE[] = "range";
const char REFERER[] = "referer";
const char RETRY_AFTER[] = "retry-after";
const char SEC_FETCH_DEST[] = "sec-fetch-dest";
const char SEC_FETCH_MODE[] = "sec-fetch-mode";
const char SEC_FETCH_SITE[] = "sec-fetch-site";
const char SEC_FETCH_USER[] = "sec-fetch-user";
const char SEC_PURPOSE[] = "sec-purpose";
const char SEC_WEBSOCKET_ACCEPT[] = "sec-websocket-accept";
const char SERVER[] = "server";
const char SERVER_TIMING[] = "server-timing";
const char SERVICE_WORKER_NAVIGATION_PRELOAD[] = "service-worker-navigation-preload";
const char SET_COOKIE[] = "set-cookie";
const char SOURCEMAP[] = "sourcemap";
const char STRICT_TRANSPORT_SECURITY[] = "strict-transport-security";
const char TE[] = "te";
const char TIMING_ALLOW_ORIGIN[] = "timing-allow-origin";
const char TRAILER[] = "trailer";
const char TRANSFER_ENCODING[] = "transfer-encoding";
const char UPGRADE[] = "upgrade";
const char UPGRADE_INSECURE_REQUESTS[] = "upgrade-insecure-requests";
const char USER_AGENT[] = "user-agent";
const char VARY[] = "vary";
const char VIA[] = "via";
const char WWW_AUTHENTICATE[] = "www-authenticate";
const char X_CUSTOM_HEADER[] = "x-custom-header";
