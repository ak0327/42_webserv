#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

ValueSet* HttpRequest::ready_ValueSet(const std::string &value)
{
	return (new ValueSet(HttpMessageParser::obtain_withoutows_value(value)));
}

// todo: Accept-Ranges
void	HttpRequest::set_accept_ranges(const std::string &key, const std::string &value)
{
	if (value == "bytes")
		this->_request_header_fields[key] = this->ready_ValueSet(value);
	else
		return;
}

// todo: Access-Control-Allow-Credentials
void	HttpRequest::set_access_control_allow_credentials(const std::string &key, const std::string &value)
{
	if (value != "true")
		return;
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Access-Control-Allow-Origin
void	HttpRequest::set_access_control_allow_origin(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Access-Control-Max-Age
void	HttpRequest::set_access_control_max_age(const std::string &key, const std::string &value)
{
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Access-Control-Request-Method
void	HttpRequest::set_access_control_request_method(const std::string &key, const std::string &value)
{
	if (value != "GET" && value != "HEAD" && value != "POST" && value != "PUT" && value != "PUT" && value != "DELETE" \
		&& value != "CONNECT" && value != "OPTIONS" && value!= "TRACE" && value != "PATCH")
		return;
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Age
void	HttpRequest::set_age(const std::string &key, const std::string &value)
{
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Alt-Used
void	HttpRequest::set_alt_used(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Connection
void	HttpRequest::set_connection(const std::string &key, const std::string &value)
{
	if (value == "close" || value == "keep-alive")
		this->_request_header_fields[key] = this->ready_ValueSet(value);
	else
		return;
}

// todo: Content-Length
void	HttpRequest::set_content_length(const std::string &key, const std::string &value)
{
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Content-Location
void	HttpRequest::set_content_location(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Content-Range
void	HttpRequest::set_content_range(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Cross-Origin-Embedder-Policy
void	HttpRequest::set_cross_origin_embedder_policy(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Cross-Origin-Opener-Policy
void	HttpRequest::set_cross_origin_opener_policy(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Cross-Origin-Resource-Policy
void	HttpRequest::set_cross_origin_resource_policy(const std::string &key, const std::string &value)
{
	if (value == "same-site" || value == "same-origin" || value == "cross-origin")
		this->_request_header_fields[key] = this->ready_ValueSet(value);
	else
		return;
}

// todo: ETag
void	HttpRequest::set_etag(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Expect
void	HttpRequest::set_expect(const std::string &key, const std::string &value)
{
	if (value == "100-continue")
		this->_request_header_fields[key] = this->ready_ValueSet(value);
	else
		return;
}

// todo: Expires
void	HttpRequest::set_expires(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: From
void	HttpRequest::set_from(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: If-Range
void	HttpRequest::set_if_range(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Location
void	HttpRequest::set_location(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Max-Forwards
void	HttpRequest::set_max_forwards(const std::string &key, const std::string &value)
{
	if (StringHandler::is_positive_and_under_intmax(value))
		this->_request_header_fields[key] = this->ready_ValueSet(value);
	else
		return;
}

// todo: Origin
void	HttpRequest::set_origin(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: Referer
void	HttpRequest::set_referer(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = this->ready_ValueSet(value);
}

// todo: ??
// void	HttpRequest::set_referrer_policy(const std::string &key, const std::string &value)
// {
// 	if (value == "no-referrer" || value == "no-referrer-when-downgrade" || value == "origin" || value == "origin-when-cross-origin" || \
// 	value == "same-origin" || value == "strict-origin" || value == "strict-origin-when-cross-origin" || value == "unsafe-url")
// 		this->_request_header_fields[key] = this->ready_ValueSet(value);
// 	else
// 		return;
// }

// todo: Retry-After
void	HttpRequest::set_retry_after(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Sec-Fetch-Dest
void	HttpRequest::set_sec_fetch_dest(const std::string &key, const std::string &value)
{
	if (value == "audio" || value == "audioworklet" || value == "document" || value == "embed" || \
	value == "empty" || value == "font" || value == "frame" || value == "iframe" || value == "image" || value == "manifest" || \
	value == "object" || value == "paintworklet" || value == "report" || value == "script" || value == "serviceworker" || \
	value == "sharedworker" || value == "style" || value == "track" || value == "video" || value == "worker" || value == "xslt")
		this->_request_header_fields[key] = ready_ValueSet(value);
	else
		return;
}

// todo: Sec-Fetch-Mode
void	HttpRequest::set_sec_fetch_mode(const std::string &key, const std::string &value)
{
	if (value == "cors" || value == "navigate" || value == "no-cors" || value == "same-origin" || value == "websocket")
		this->_request_header_fields[key] = ready_ValueSet(value);
	else
		return;
}

// todo: Sec-Fetch-Site
void	HttpRequest::set_sec_fetch_site(const std::string &key, const std::string &value)
{
	if (value == "cross-site" || value == "same-origin" || value == "same-site" || value == "none")
		this->_request_header_fields[key] = ready_ValueSet(value);
	else
		return;
}

// todo: Sec-Fetch-User
void	HttpRequest::set_sec_fetch_user(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Sec-Purpose
void	HttpRequest::set_sec_purpose(const std::string &key, const std::string &value)
{
	if (value == "prefetch")
		this->_request_header_fields[key] = ready_ValueSet(value);
	else
		return;
}

// todo: Sec-WebSocket-Accept
void	HttpRequest::set_sec_websocket_accept(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Server
void	HttpRequest::set_server(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Service-Worker-Navigation-Preload
void	HttpRequest::set_service_worker_navigation_preload(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: SourceMap
void	HttpRequest::set_sourcemap(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Timing-Allow-Origin
void	HttpRequest::set_timing_allow_origin(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Trailer
void	HttpRequest::set_trailer(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}


// todo: Upgrade-Insecure-Requests
void	HttpRequest::set_upgrade_insecure_requests(const std::string &key, const std::string &value)
{
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	if (StringHandler::is_positive_and_under_intmax(value) == false)
		return;
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: User-Agent
void	HttpRequest::set_user_agent(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}

// todo: Via
void	HttpRequest::set_via(const std::string &key, const std::string &value)
{
	this->_request_header_fields[key] = ready_ValueSet(value);
}
