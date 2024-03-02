#include <string>
#include "Constant.hpp"

////////////////////////////////////////////////////////////////////////////////
/* return value */

const int OK = 0;
const int ERR = -1;
const int CGI = 1;
const int CONTINUE = 2;
const int PROCESS_TIMEOUT = 256;

const int GETADDRINFO_SUCCESS = 0;
const int REMOVE_SUCCESS = 0;

const ssize_t RECV_COMPLETED = 0;
const ssize_t RECV_CONTINUE = -1;
const ssize_t RECV_ERROR = -1;

const ssize_t SEND_COMPLETED = 0;
const ssize_t SEND_CONTINUE = -1;
const ssize_t SEND_ERROR = -1;

const int ACCEPT_ERROR = -1;
const int BIND_ERROR = -1;
const int CLOSE_ERROR = -1;
const int CONN_ERROR = -1;
const int DUP_ERROR = -1;
const int EXECVE_ERROR = -1;
const int FCNTL_ERROR = -1;
const int FORK_ERROR = -1;
const int KILL_ERROR = -1;
const int LISTEN_ERROR = -1;
const int SETSOCKOPT_ERROR = -1;
const int SOCKET_ERROR = -1;
const int SOCKETPAIR_ERROR = -1;
const int STAT_ERROR = -1;


const pid_t PROCESSING = 0;
const pid_t WAIT_ERROR = -1;

const pid_t CHILD_PROC = 0;
const std::size_t READ = 0;
const std::size_t WRITE = 1;

////////////////////////////////////////////////////////////////////////////////
/* initial value */

const int COUNTER_INIT = 0;
const int INIT_FD = -1;
const int INIT_PID = -1;
const int FLAG_NONE = 0;

const double WEIGHT_INIT = 1.0;

////////////////////////////////////////////////////////////////////////////////

/* num */
const int SINGLE_OCCURRENCE_LIMIT = 1;
const int PORT_MIN = 0;
const int PORT_MAX = 65535;

const int IO_TIMEOUT = -1;

const int OFFSET_NONE = 0;

const std::size_t FILE_SIZE_LIMIT = 65535;

////////////////////////////////////////////////////////////////////////////////
/* status */

const int STATUS_OK = 200;
const int STATUS_BAD_REQUEST = 400;
const int REQUEST_ENTITY_TOO_LARGE = 413;
const int STATUS_SERVER_ERROR = 500;

const std::map<StatusCode, std::string> STATUS_REASON_PHRASES = init_reason_phrases();

std::map<StatusCode, std::string> init_reason_phrases() {
    std::map<StatusCode, std::string> reason_phrases;
    // reason_phrases[] = "";

    reason_phrases[StatusOk]                = "OK";
    reason_phrases[Created]                 = "Created";
    reason_phrases[NoContent]               = "No Content";

    reason_phrases[MultipleChoices]         = "Multiple Choices";
    reason_phrases[MovedPermanently]        = "Moved Permanently";
    reason_phrases[SeeOther]                = "See Other";

    reason_phrases[BadRequest]              = "Bad Request";
    reason_phrases[Unauthorized]            = "Unauthorized";
    reason_phrases[Forbidden]               = "Forbidden";
    reason_phrases[NotFound]                = "Not Found";
    reason_phrases[MethodNotAllowed]        = "Method Not Allowed";
    reason_phrases[NotAcceptable]           = "Not Acceptable";
    reason_phrases[RequestTimeout]          = "Request Timeout";
    reason_phrases[Conflict]                = "Conflict";
    reason_phrases[LengthRequired]          = "Length Required";
    reason_phrases[ContentTooLarge]         = "Content Too Large";

    reason_phrases[InternalServerError]     = "Internal Server Error";
    reason_phrases[NotImplemented]          = "Not Implemented";
    reason_phrases[BadGateway]              = "Bad Gateway";
    reason_phrases[ServiceUnavailable]      = "Service Unavailable";
    reason_phrases[GatewayTimeout]          = "Gateway Timeout";
    reason_phrases[HTTPVersionNotSupported] = "HTTP Version Not Supported";

    return reason_phrases;
}

////////////////////////////////////////////////////////////////////////////////
/* char */

const char COLON = ':';
const char COMMA = ',';
const char SEMICOLON = ';';
const char DOUBLE_QUOTE = '"';
const char EQUAL_SIGN = '=';
const char SINGLE_QUOTE = '\'';
const char SLASH = '/';
const char LBRACES = '{';
const char RBRACES = '}';
const char COMMENT_SYMBOL = '#';

const char PATH_DELIM = '/';
const char EXTENSION_DELIM = '.';

const char ELEMENT_SEPARATOR = COMMA;

const char EMPTY[] = "";
const char TIMEOUT[] = "timeout";

const char CONFIG_FILE_EXTENSION[] = "conf";

////////////////////////////////////////////////////////////////////////////////
/* error message */

const char INVALID_ARG_ERROR_MSG[] = "[Error] invalid argument";
const char INVALID_PATH_ERROR_MSG[] = "[Error] invalid file path";
const char FILE_SIZE_TOO_LARGE_ERROR_MSG[] = "[Error] file size too large";

////////////////////////////////////////////////////////////////////////////////
/* http message */

const char DECIMAL_POINT = '.';
const char SIGN_PLUS = '+';
const char SIGN_MINUS = '-';

const char CR = '\r';
const char HT = '\t';
const char LF = '\n';
const char NL = '\n';
const char SP = ' ';

const char CRLF[] = "\r\n";

////////////////////////////////////////////////////////////////////////////////
/* method */

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
/* http version */

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
/* field name */

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
const char SEC_CH_UA[] = "sec-ch-ua";
const char SEC_CH_UA_MOBILE[] = "sec-ch-ua-mobile";
const char SEC_CH_UA_PLATFORM[] = "sec-ch-ua-platform";
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

const std::vector<std::string> FIELD_NAMES = init_field_names();
const std::vector<std::string> MESSAGE_FRAMING_HEADERS = init_message_framing_headers();
const std::vector<std::string> ROUTING_HEADERS = init_routing_headers();
const std::vector<std::string> REQUEST_MODIFIERS = init_request_modifiers();
const std::vector<std::string> AUTHENTICATION_HEADERS = init_authentication_headers();
const std::vector<std::string> IGNORE_HEADERS = init_ignore_headers();

std::vector<std::string> init_field_names() {
	std::vector<std::string> field_names;

	field_names.push_back(std::string(ACCEPT));
	field_names.push_back(std::string(ACCEPT_CH));
	field_names.push_back(std::string(ACCEPT_CHARSET));
	field_names.push_back(std::string(ACCEPT_ENCODING));
	field_names.push_back(std::string(ACCEPT_LANGUAGE));
	field_names.push_back(std::string(ACCEPT_PATCH));
	field_names.push_back(std::string(ACCEPT_POST));
	field_names.push_back(std::string(ACCEPT_RANGES));
	field_names.push_back(std::string(ACCESS_CONTROL_ALLOW_CREDENTIALS));
	field_names.push_back(std::string(ACCESS_CONTROL_ALLOW_HEADERS));
	field_names.push_back(std::string(ACCESS_CONTROL_ALLOW_METHODS));
	field_names.push_back(std::string(ACCESS_CONTROL_ALLOW_ORIGIN));
	field_names.push_back(std::string(ACCESS_CONTROL_EXPOSE_HEADERS));
	field_names.push_back(std::string(ACCESS_CONTROL_MAX_AGE));
	field_names.push_back(std::string(ACCESS_CONTROL_REQUEST_HEADERS));
	field_names.push_back(std::string(ACCESS_CONTROL_REQUEST_METHOD));
	field_names.push_back(std::string(AGE));
	field_names.push_back(std::string(ALLOW));
	field_names.push_back(std::string(ALT_SVC));
	field_names.push_back(std::string(ALT_USED));
	field_names.push_back(std::string(AUTHORIZATION));
	field_names.push_back(std::string(CACHE_CONTROL));
	field_names.push_back(std::string(CLEAR_SITE_DATA));
	field_names.push_back(std::string(CONNECTION));
	field_names.push_back(std::string(CONTENT_DISPOSITION));
	field_names.push_back(std::string(CONTENT_ENCODING));
	field_names.push_back(std::string(CONTENT_LANGUAGE));
	field_names.push_back(std::string(CONTENT_LENGTH));
	field_names.push_back(std::string(CONTENT_LOCATION));
	field_names.push_back(std::string(CONTENT_RANGE));
	field_names.push_back(std::string(CONTENT_SECURITY_POLICY));
	field_names.push_back(std::string(CONTENT_SECURITY_POLICY_REPORT_ONLY));
	field_names.push_back(std::string(CONTENT_TYPE));
	field_names.push_back(std::string(COOKIE));
	field_names.push_back(std::string(CROSS_ORIGIN_EMBEDDER_POLICY));
	field_names.push_back(std::string(CROSS_ORIGIN_OPENER_POLICY));
	field_names.push_back(std::string(CROSS_ORIGIN_RESOURCE_POLICY));
	field_names.push_back(std::string(DATE));
	field_names.push_back(std::string(ETAG));
	field_names.push_back(std::string(EXPECT));
	field_names.push_back(std::string(EXPECT_CT));
	field_names.push_back(std::string(EXPIRES));
	field_names.push_back(std::string(FORWARDED));
	field_names.push_back(std::string(FROM));
	field_names.push_back(std::string(HOST));
	field_names.push_back(std::string(IF_MATCH));
	field_names.push_back(std::string(IF_MODIFIED_SINCE));
	field_names.push_back(std::string(IF_NONE_MATCH));
	field_names.push_back(std::string(IF_RANGE));
	field_names.push_back(std::string(IF_UNMODIFIED_SINCE));
	field_names.push_back(std::string(KEEP_ALIVE));
	field_names.push_back(std::string(LAST_MODIFIED));
	field_names.push_back(std::string(LINK));
	field_names.push_back(std::string(LOCATION));
	field_names.push_back(std::string(MAX_FORWARDS));
	field_names.push_back(std::string(ORIGIN));
	field_names.push_back(std::string(PERMISSION_POLICY));
	field_names.push_back(std::string(PROXY_AUTHENTICATE));
	field_names.push_back(std::string(PROXY_AUTHORIZATION));
	field_names.push_back(std::string(RANGE));
	field_names.push_back(std::string(REFERER));
	field_names.push_back(std::string(RETRY_AFTER));
	field_names.push_back(std::string(SEC_FETCH_DEST));
	field_names.push_back(std::string(SEC_FETCH_MODE));
	field_names.push_back(std::string(SEC_FETCH_SITE));
	field_names.push_back(std::string(SEC_FETCH_USER));
	field_names.push_back(std::string(SEC_PURPOSE));
	field_names.push_back(std::string(SEC_WEBSOCKET_ACCEPT));
	field_names.push_back(std::string(SERVER));
	field_names.push_back(std::string(SERVER_TIMING));
	field_names.push_back(std::string(SERVICE_WORKER_NAVIGATION_PRELOAD));
	field_names.push_back(std::string(SET_COOKIE));
	field_names.push_back(std::string(SOURCEMAP));
	field_names.push_back(std::string(STRICT_TRANSPORT_SECURITY));
	field_names.push_back(std::string(TE));
	field_names.push_back(std::string(TIMING_ALLOW_ORIGIN));
	field_names.push_back(std::string(TRAILER));
	field_names.push_back(std::string(TRANSFER_ENCODING));
	field_names.push_back(std::string(UPGRADE));
	field_names.push_back(std::string(UPGRADE_INSECURE_REQUESTS));
	field_names.push_back(std::string(USER_AGENT));
	field_names.push_back(std::string(VARY));
	field_names.push_back(std::string(VIA));
	field_names.push_back(std::string(WWW_AUTHENTICATE));
	field_names.push_back(std::string(X_CUSTOM_HEADER));
	return field_names;
}

std::vector<std::string> init_message_framing_headers() {
	std::vector<std::string> message_framing_headers;

	message_framing_headers.push_back(TRANSFER_ENCODING);
	message_framing_headers.push_back(CONTENT_LENGTH);
	return message_framing_headers;
}

std::vector<std::string> init_routing_headers() {
	std::vector<std::string> routing_headers;

	routing_headers.push_back(HOST);
	return routing_headers;
}

std::vector<std::string> init_request_modifiers() {
	std::vector<std::string> request_modifiers;

	request_modifiers.push_back(CACHE_CONTROL);
	request_modifiers.push_back(MAX_FORWARDS);
	request_modifiers.push_back(TE);
	return request_modifiers;
}

std::vector<std::string> init_authentication_headers() {
	std::vector<std::string> authentication_headers;

	authentication_headers.push_back(AUTHORIZATION);
	authentication_headers.push_back(SET_COOKIE);
	return authentication_headers;
}

std::vector<std::string> init_ignore_headers() {
	std::vector<std::string> ignore_headers;

	ignore_headers.push_back(ACCEPT_CHARSET);
    ignore_headers.push_back(SEC_CH_UA);            // for chrome
    ignore_headers.push_back(SEC_CH_UA_MOBILE);     // for chrome
    ignore_headers.push_back(SEC_CH_UA_PLATFORM);   // for chrome
	return ignore_headers;
}

////////////////////////////////////////////////////////////////////////////////
/* field value */

const char AUTH_SCHEME[] = "auth_scheme";
const char AUTH_PARAM[] = "auth_param";

const char URI_HOST[] = "uri_host";
const char PORT[] = "port";

const char RECEIVED_PROTOCOL[] = "received_protocol";
const char RECEIVED_BY[] = "received_by";
const char COMMENT[] = "comment";

const char URI_REFERENCE[] = "uri_reference";

const char WEIGHT_KEY[] = "q";

////////////////////////////////////////////////////////////////////////////////
/* date */

const char GMT[] = "GMT";
const char MON[] = "Mon";
const char TUE[] = "Tue";
const char WED[] = "Wed";
const char THU[] = "Thu";
const char FRI[] = "Fri";
const char SAT[] = "Sat";
const char SUN[] = "Sun";

const char JAN[] = "Jan";
const char FEB[] = "Feb";
const char MAR[] = "Mar";
const char APR[] = "Apr";
const char MAY[] = "May";
const char JUN[] = "Jun";
const char JUL[] = "Jul";
const char AUG[] = "Aug";
const char SEP[] = "Sep";
const char OCT[] = "Oct";
const char NOV[] = "Nov";
const char DEC[] = "Dec";

const int GREGORIAN_CALENDAR = 1582;

const std::vector<std::string> DAY_NAMES = init_day_names();
const std::vector<std::string> MONTHS = init_months();

std::vector<std::string> init_day_names() {
	std::vector<std::string> day_names;

	day_names.push_back(std::string(MON));
	day_names.push_back(std::string(TUE));
	day_names.push_back(std::string(WED));
	day_names.push_back(std::string(THU));
	day_names.push_back(std::string(FRI));
	day_names.push_back(std::string(SAT));
	day_names.push_back(std::string(SUN));
	return day_names;
}

std::vector<std::string> init_months() {
	std::vector<std::string> months;

	months.push_back(std::string(JAN));
	months.push_back(std::string(FEB));
	months.push_back(std::string(MAR));
	months.push_back(std::string(APR));
	months.push_back(std::string(MAY));
	months.push_back(std::string(JUN));
	months.push_back(std::string(JUL));
	months.push_back(std::string(AUG));
	months.push_back(std::string(SEP));
	months.push_back(std::string(OCT));
	months.push_back(std::string(NOV));
	months.push_back(std::string(DEC));
	return months;
}

////////////////////////////////////////////////////////////////////////////////

const std::vector<std::string> SH_TOKENS = init_sh_tokens();

std::vector<std::string> init_sh_tokens() {
	std::vector<std::string> sh_tokens;

	sh_tokens.push_back("audio");
	sh_tokens.push_back("audioworklet");
	sh_tokens.push_back("document");
	sh_tokens.push_back("embed");
	sh_tokens.push_back("empty");
	sh_tokens.push_back("font");
	sh_tokens.push_back("frame");
	sh_tokens.push_back("iframe");
	sh_tokens.push_back("image");
	sh_tokens.push_back("manifest");
	sh_tokens.push_back("object");
	sh_tokens.push_back("paintworklet");
	sh_tokens.push_back("report");
	sh_tokens.push_back("script");
	sh_tokens.push_back("serviceworker");
	sh_tokens.push_back("sharedworker");
	sh_tokens.push_back("style");
	sh_tokens.push_back("track");
	sh_tokens.push_back("video");
	sh_tokens.push_back("worker");
	sh_tokens.push_back("xslt");
	return sh_tokens;
}

////////////////////////////////////////////////////////////////////////////////
/* configuration */

const char EVENTS_BLOCK[] = "events";
const char HTTP_BLOCK[] = "http";
const char SERVER_BLOCK[] = "server";
const char LOCATION_BLOCK[] = "location";

const char LISTEN_DIRECTIVE[] = "listen";
const char SERVER_NAME_DIRECTIVE[] = "server_name";
const char RETURN_DIRECTIVE[] = "return";

const char ROOT_DIRECTIVE[] = "root";
const char INDEX_DIRECTIVE[] = "index";
const char LIMIT_EXCEPT_DIRECTIVE[] = "limit_except";
const char ERROR_PAGE_DIRECTIVE[] = "error_page";
const char AUTOINDEX_DIRECTIVE[] = "autoindex";
const char BODY_SIZE_DIRECTIVE[] = "client_max_body_size";

const char ALLOW_DIRECTIVE[] = "allow";
const char DENY_DIRECTIVE[] = "deny";

const char CGI_MODE_DIRECTIVE[] = "cgi_mode";
const char CGI_EXTENSION_DIRECTIVE[] = "cgi_extension";
const char CGI_TIMEOUT_DIRECTIVE[] = "cgi_timeout";

const char LEFT_PAREN[] = "{";
const char RIGHT_PAREN[] = "}";

const std::vector<std::string> BLOCK_NAMES = init_block_names();
const std::vector<std::string> DIRECTIVE_NAMES = init_directive_names();

std::vector<std::string> init_block_names() {
	std::vector<std::string> block_names;

	block_names.push_back(EVENTS_BLOCK);
	block_names.push_back(HTTP_BLOCK);
	block_names.push_back(SERVER_BLOCK);
	block_names.push_back(LOCATION_BLOCK);
	return block_names;
}

std::vector<std::string> init_directive_names() {
	std::vector<std::string> directive_names;

	directive_names.push_back(LISTEN_DIRECTIVE);
	directive_names.push_back(SERVER_NAME_DIRECTIVE);
	directive_names.push_back(ERROR_PAGE_DIRECTIVE);
	directive_names.push_back(BODY_SIZE_DIRECTIVE);
	directive_names.push_back(RETURN_DIRECTIVE);
	directive_names.push_back(ROOT_DIRECTIVE);
	directive_names.push_back(AUTOINDEX_DIRECTIVE);
	directive_names.push_back(INDEX_DIRECTIVE);
	directive_names.push_back(LIMIT_EXCEPT_DIRECTIVE);
	directive_names.push_back(ALLOW_DIRECTIVE);     // inside limit_except
	directive_names.push_back(DENY_DIRECTIVE);      // inside limit_except
	directive_names.push_back(CGI_MODE_DIRECTIVE);
	directive_names.push_back(CGI_EXTENSION_DIRECTIVE);
	directive_names.push_back(CGI_TIMEOUT_DIRECTIVE);
	return directive_names;
}

////////////////////////////////////////////////////////////////////////////////
/* mime types */

const MimeTypeMap MIME_TYPES = init_mime_types();
MimeTypeMap init_mime_types() {
    MimeTypeMap mime_types;
    // mime_types[""] = "";

    mime_types["html"]  = "text/html";
    mime_types["htm"]   = "text/htm";
    mime_types["css"]   = "text/css";
    mime_types["txt"]   = "text/plain";
    mime_types["py"]    = "text/x-python";

    mime_types["gif"]   = "image/gif";
    mime_types["jpeg"]  = "image/jpeg";
    mime_types["jpg"]   = "image/jpg";
    mime_types["png"]   = "image/png";
    mime_types["ico"]   = "image/x-ico";

    mime_types["json"]  = "application/json";  // todo

    return mime_types;
}

////////////////////////////////////////////////////////////////////////////////
/* API endpoint */

const std::vector<std::string> API_ENDPOINTS = init_endpoints();

std::vector<std::string> init_endpoints() {
    std::vector<std::string> endpoints;
    // endpoints.push_back("");

    endpoints.push_back("/api/form-data");
    endpoints.push_back("/api/show-response");
    endpoints.push_back("/api/now");
    return endpoints;
}

////////////////////////////////////////////////////////////////////////////////
/* server information */

const char SERVER_SEMANTIC_VERSION[] = "webserv/1.0.0";
