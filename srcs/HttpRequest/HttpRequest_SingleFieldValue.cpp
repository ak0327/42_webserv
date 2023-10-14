#include <algorithm>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

namespace {

std::size_t count(const std::vector<std::string> &vec,
				  const std::string &target) {
	return std::count(vec.begin(), vec.end(), target);
}

bool is_trailer_allowed_field_name(const std::string &field_name) {
	if (count(MESSAGE_FRAMING_HEADERS, field_name) != 0) {
		return false;
	}
	if (count(ROUTING_HEADERS, field_name) != 0) {
		return false;
	}
	if (count(REQUEST_MODIFIERS, field_name) != 0) {
		return false;
	}
	if (count(AUTHENTICATION_HEADERS, field_name) != 0) {
		return false;
	}
	if (field_name == CONTENT_ENCODING
		|| field_name == CONTENT_TYPE
		|| field_name == CONTENT_RANGE
		|| field_name == TRAILER) {
		return false;
	}
	return true;
}

}  // namespace

// Access-Control-Request-Method: <method>
Result<int, int> HttpRequest::set_access_control_request_method(const std::string &field_name,
																const std::string &field_value) {
	clear_field_values_of(field_name);

	if (HttpMessageParser::is_valid_method(field_value)) {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Alt-Used
// Alt-Used = uri-host [ ":" port ]
// https://tex2e.github.io/rfc-translater/html/rfc7838.html#5--The-Alt-Used-HTTP-Header-Field

// todo: map['host'] = host, map[port] = port ?
// same as Host structure
Result<int, int> HttpRequest::set_alt_used(const std::string &field_name,
										   const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// Connection        = #connection-option; case-insensitive
// connection-option = token

// Connection: keep-alive
// Connection: close
Result<int, int> HttpRequest::set_connection(const std::string &field_name,
											 const std::string &field_value) {
	std::string lower_field_value;

	clear_field_values_of(field_name);

	lower_field_value = StringHandler::to_lower(field_value);
	if (lower_field_value == "close" || lower_field_value == "keep-alive") {
		this->_request_header_fields[field_name] = new SingleFieldValue(lower_field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Content-Length: <length>
// todo: 受信したメッセージが［ Transfer-Encoding, Content-Length ］の両ヘッダを伴う場合、
//  Transfer-Encoding が Content-Length を上書きする
// 妥当でない値をとる Content-Length ヘッダが在る -> サーバは、状態コード 400 (Bad Request) で応答した上で，接続を close する
// todo: ng -> close
Result<int, int> HttpRequest::set_content_length(const std::string &field_name,
												 const std::string &field_value) {
	bool succeed;
	long length;
	std::string num_str;

	if (has_multiple_field_names(field_name)) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	length = HttpMessageParser::to_length(field_value, &succeed);
	if (!succeed) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	num_str = StringHandler::to_string(length);
	this->_request_header_fields[field_name] = new SingleFieldValue(num_str);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Content-Location
// Content-Location = absolute-URI / partial-URI
//   absolute-URI  = scheme ":" hier-part [ "?" query ]
//   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
Result<int, int> HttpRequest::set_content_location(const std::string &field_name,
												   const std::string &field_value) {
	clear_field_values_of(field_name);

	if (HttpMessageParser::is_absolute_uri(field_value)
		|| HttpMessageParser::is_partial_uri(field_value)) {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Content-Range
// Content-Range: <unit> <range-start>-<range-end>/<size>
// Content-Range: <unit> <range-start>-<range-end>/*
// Content-Range: <unit> */<size>
Result<int, int> HttpRequest::set_content_range(const std::string &field_name,
												const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// Expect  = "100-continue" ;case-insensitive.
Result<int, int> HttpRequest::set_expect(const std::string &field_name,
										 const std::string &field_value) {
	std::string lower_field_value;

	if (has_multiple_field_names(field_name)) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	lower_field_value = StringHandler::to_lower(field_value);
	if (lower_field_value == "100-continue") {
		this->_request_header_fields[field_name] = new SingleFieldValue(lower_field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Expires
// Expires: <http-date>
Result<int, int> HttpRequest::set_expires(const std::string &field_name,
										  const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: From
// From    = mailbox
// mailbox         =   name-addr / addr-spec
// name-addr       =   [display-name] angle-addr
// angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
//
// addr-spec       =   local-part "@" domain
// local-part      =   dot-atom / quoted-string / obs-local-part
// domain          =   dot-atom / domain-literal / obs-domain
// domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
// dtext           =   %d33-90 /          ; Printable US-ASCII
//                     %d94-126 /         ; characters not including
//                     obs-dtext          ; "[", "]", or "\"
//
// obs-angle-addr  =   [CFWS] "<" obs-route addr-spec ">" [CFWS]
// obs-route       =   obs-domain-list ":"
// obs-domain-list =   *(CFWS / ",") "@" domain
//                     *("," [CFWS] ["@" domain])
Result<int, int> HttpRequest::set_from(const std::string &field_name,
									   const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: If-Range
// If-Range	= entity-tag / HTTP-date
// todo: サーバは、 Range ヘッダを包含しない要請内に受信された If-Range ヘッダを，無視しなければならない。
Result<int, int> HttpRequest::set_if_range(const std::string &field_name,
										   const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// Max-Forwards = 1*DIGIT
Result<int, int> HttpRequest::set_max_forwards(const std::string &field_name,
											   const std::string &field_value) {
	int max_forwards;
	bool succeed;
	std::string num_str;

	clear_field_values_of(field_name);

	max_forwards = HttpMessageParser::to_integer_num(field_value, &succeed);
	if (succeed) {
		num_str = StringHandler::to_string(max_forwards);
		this->_request_header_fields[field_name] = new SingleFieldValue(num_str);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Origin
// Origin: null
// Origin: <scheme>://<hostname>
// Origin: <scheme>://<hostname>:<port>
Result<int, int> HttpRequest::set_origin(const std::string &field_name,
										 const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Referer
// Referer = absolute-URI / partial-URI
Result<int, int> HttpRequest::set_referer(const std::string &field_name,
										  const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: ??
/*
Result<int, int> HttpRequest::set_referrer_policy(const std::string &field_name, const std::string &field_value)
{
	if (field_value == "no-referrer" || field_value == "no-referrer-when-downgrade" || field_value == "origin" || field_value == "origin-when-cross-origin" || \
	field_value == "same-origin" || field_value == "strict-origin" || field_value == "strict-origin-when-cross-origin" || field_value == "unsafe-url")
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	else
		return;
}
 */

// todo: Sec-Fetch-Dest
Result<int, int> HttpRequest::set_sec_fetch_dest(const std::string &field_name,
												 const std::string &field_value)
{
	if (field_value == "audio" || field_value == "audioworklet" || field_value == "document"
	|| field_value == "embed" || field_value == "empty" || field_value == "font"
	|| field_value == "frame" || field_value == "iframe" || field_value == "image"
	|| field_value == "manifest" || field_value == "object" || field_value == "paintworklet"
	|| field_value == "report" || field_value == "script" || field_value == "serviceworker"
	|| field_value == "sharedworker" || field_value == "style" || field_value == "track"
	|| field_value == "video" || field_value == "worker" || field_value == "xslt")
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	// else
	// 	return;
	return Result<int, int>::ok(STATUS_OK);
}

// Sec-Fetch-Mode: cors / navigate / no-cors / same-origin / websocket
// The Sec-Fetch-Mode HTTP request header exposes a request's mode to a server.
// It is a Structured Header whose value is a token.
// [I-D.ietf-httpbis-header-structure] Its ABNF is:
//
// Sec-Fetch-Mode = sh-token
// Valid Sec-Fetch-Mode values include
// "cors", "navigate", "no-cors", "same-origin", and "websocket".
// In order to support forward-compatibility with as-yet-unknown request types,
// servers SHOULD ignore this header if it contains an invalid value.
Result<int, int> HttpRequest::set_sec_fetch_mode(const std::string &field_name,
												 const std::string &field_value) {
	clear_field_values_of(field_name);

	if (field_value == "cors"
		|| field_value == "navigate"
		|| field_value == "no-cors"
		|| field_value == "same-origin"
		|| field_value == "websocket") {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Sec-Fetch-Site: cross-site / same-origin / same-site / none
Result<int, int> HttpRequest::set_sec_fetch_site(const std::string &field_name,
												 const std::string &field_value) {
	clear_field_values_of(field_name);

	if (field_value == "cross-site"
	|| field_value == "same-origin"
	|| field_value == "same-site"
	|| field_value == "none") {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Sec-Fetch-User: ?1
Result<int, int> HttpRequest::set_sec_fetch_user(const std::string &field_name,
												 const std::string &field_value) {
	clear_field_values_of(field_name);
	if (field_value == "?1") {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Sec-Purpose: prefetch
Result<int, int> HttpRequest::set_sec_purpose(const std::string &field_name,
											  const std::string &field_value) {
	clear_field_values_of(field_name);
	if (field_value == "prefetch") {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}


// Service-Worker-Navigation-Preload: <value>
// <value>; An arbitrary value that
// indicates what data should be sent in the response to the preload request.
// This defaults to true.
Result<int, int> HttpRequest::set_service_worker_navigation_preload(const std::string &field_name,
																	const std::string &field_value) {
	clear_field_values_of(field_name);
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// Trailer = #field-name
Result<int, int> HttpRequest::set_trailer(const std::string &field_name,
										  const std::string &field_value) {
	std::string lower_field_value;

	clear_field_values_of(field_name);

	lower_field_value = StringHandler::to_lower(field_value);
	if (is_trailer_allowed_field_name(lower_field_value)) {
		this->_request_header_fields[field_name] = new SingleFieldValue(lower_field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Upgrade-Insecure-Requests: 1
Result<int, int> HttpRequest::set_upgrade_insecure_requests(const std::string &field_name,
															const std::string &field_value) {
	clear_field_values_of(field_name);

	if (field_value == "1") {
		this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: User-Agent
// User-Agent = product *( RWS ( product / comment ) )
// product         = token ["/" product-version]
// product-version = token
Result<int, int> HttpRequest::set_user_agent(const std::string &field_name,
											 const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Via
// Via: [ <protocol-name> "/" ] <protocol-version> <host> [ ":" <port> ]
//  or
// Via: [ <protocol-name> "/" ] <protocol-version> <pseudonym>

// Via = 1#( received-protocol RWS received-by [ RWS comment ] )

// received-protocol = [ protocol-name "/" ] protocol-version
//                     ; see Section 6.7
// received-by       = ( uri-host [ ":" port ] ) / pseudonym
// pseudonym         = token
Result<int, int> HttpRequest::set_via(const std::string &field_name,
									  const std::string &field_value)
{
	this->_request_header_fields[field_name] = new SingleFieldValue(field_value);
	return Result<int, int>::ok(STATUS_OK);
}
