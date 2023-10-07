#include "HttpRequest.hpp"

HttpRequest::HttpRequest(const std::string &all_request_text):_status_code(200)
{
	std::string			line;
	std::string			remove_crlf_word;
	std::string			key;
	std::string			field_value;
	std::stringstream	ss(all_request_text);

	ready_functionmap();
	std::getline(ss, line, '\n');
	if (this->is_requestlineformat(line) == false)
	{
		this->_status_code = 400;
		return;
	}
	this->_request_line.set_value(line);
	while (std::getline(ss, line, '\n'))
	{
		if (StringHandler::is_end_with_cr(line) == false)
		{
			this->_status_code = 400;
			return;
		}
		remove_crlf_word = line.substr(0, line.length() - 1);
		if (is_requestformat(line) == false)
		{
			this->_status_code = 400;
			return;
		}
		if (StringHandler::is_printable_content(remove_crlf_word) == false)
		{
			this->_status_code = 400;
			return;
		}
		key = this->obtain_request_key(line);
		field_value = this->obtain_request_value(line);
		field_value = field_value.substr(0, field_value.length() - 1);
		if (this->is_keyword_exist(key) == true)
			(this->*_field_name_parser[key])(key, field_value);
	}
}

HttpRequest::~HttpRequest()
{
	std::map<std::string, BaseKeyValueMap*>::iterator inputed_class_itr = this->_request_keyvalue_map.begin();

	while (inputed_class_itr != this->_request_keyvalue_map.end())
	{
		delete (inputed_class_itr->second);
		inputed_class_itr++;
	}
}

/*
request-line
	= method SP request-target SP HTTP-version
*/
bool HttpRequest::is_requestlineformat(std::string input_requestline)
{
	int			i = 0;
	size_t		pos = 0;

	if (std::count(input_requestline.begin(), input_requestline.end(), ' ') != 2)
		return (false);
	while (i != 3)
	{
		if (input_requestline[pos] == ' ')
			return (false);
		if (i == 2)
		{
			if (StringHandler::is_end_with_cr(input_requestline.substr(pos)) == false)
				return (false);
			if (input_requestline.substr(pos, input_requestline.length() - pos - 1).find(' ') != std::string::npos)
				return (false);
		}
		while (input_requestline[pos] != ' ' && pos != input_requestline.length() - 1)
		{
			if (isprint(input_requestline[pos]) == false)
				return false;
			pos++;
		}
		if (i != 2)
			pos++;
		i++;
	}
	return (true);
}

bool	HttpRequest::is_keyword_exist(const std::string &key)
{
	if (this->_field_name_parser.count(key) > 0)
		return true;
	return false;
}

std::string	HttpRequest::obtain_request_key(const std::string value)
{
	std::stringstream	ss(value);
	std::string			line;

	std::getline(ss, line, ':');
	return (line);
}

bool	HttpRequest::is_requestformat(const std::string &val)
{
	std::string::size_type pos = val.find_first_of(":");

	if (pos == 0 || pos == std::string::npos)
		return (false);
	if (StringHandler::is_ows(val[pos - 1]))
		return (false);
	return (true);
}

std::string	HttpRequest::obtain_request_value(const std::string value)
{
	std::string::size_type pos = value.find_first_of(":");
	std::string part2 = value.substr(pos + 2);

	return (part2);
}

// weightarrayset わかりやすいように

bool	HttpRequest::is_weightformat(const std::string &value)
{
	size_t		semicolon_pos = value.find(';');
	std::string	field_value_weight = value.substr(semicolon_pos + 1);
	std::string	weight_key;
	std::string	weight_num;

	if (std::count(field_value_weight.begin(), field_value_weight.end(), '=') != 1)
		return (false);
	weight_key = field_value_weight.substr(0, field_value_weight.find('='));
	if (weight_key != "q")
		return (false);
	weight_num = field_value_weight.substr(field_value_weight.find('=') + 1);
	return StringHandler::is_positive_under_intmax_double(weight_num);
}

// まだできてない
void	HttpRequest::set_cache_control(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// Digest username=<username>,realm="<realm>",uri="<url>",algorithm=<algorithm>,nonce="<nonce>",
	// ValueMapに変更
	// this->_request_keyvalue_map[key] = ready_ValueWeightArraySet(value);
}

void	HttpRequest::set_content_security_policy_report_only(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
	// std::cout << key << " and " << "value is " << value << std::endl;
	// this->_request_keyvalue_map[key] = ready_SecurityPolicy();
}

void	HttpRequest::set_servertiming(const std::string &key, const std::string &value)
{
	// cpu;dur=2.4;a=b, cpu; ,,,みたいな感じなのでmapで保持しないほうがいいかもしれない
	// this->_request_keyvalue_map[key] = ready_ValueMap(value);
	(void)key;
	(void)value;
}

void	HttpRequest::set_x_xss_protection(const std::string &key, const std::string &value)
{
	(void)key;
	(void)value;
}

void HttpRequest::ready_functionmap()
{
	this->_field_name_parser["Accept"] = &HttpRequest::set_accept;
	this->_field_name_parser["Accept-CH"] = &HttpRequest::set_accept_ch;
	this->_field_name_parser["Accept-Charset"] = &HttpRequest::set_accept_charset;
	this->_field_name_parser["Accept-Encoding"] = &HttpRequest::set_accept_encoding;
	this->_field_name_parser["Accept-Language"] = &HttpRequest::set_accept_language;
	// this->_field_name_parser["Accept-Patch"] = this->set_accept_patch;
	this->_field_name_parser["Accept-Post"] = &HttpRequest::set_accept_post;
	this->_field_name_parser["Accept-Ranges"] = &HttpRequest::set_accept_ranges;
	this->_field_name_parser["Access-Control-Allow-Credentials"] = &HttpRequest::set_access_control_allow_credentials;
	this->_field_name_parser["Access-Control-Allow-Headers"] = &HttpRequest::set_access_control_allow_headers;
	this->_field_name_parser["Access-Control-Allow-Methods"] = &HttpRequest::set_access_control_allow_methods;
	this->_field_name_parser["Access-Control-Allow-Origin"] = &HttpRequest::set_access_control_allow_origin;
	this->_field_name_parser["Access-Control-Expose-Headers"] = &HttpRequest::set_access_control_expose_headers;
	this->_field_name_parser["Access-Control-Max-Age"] = &HttpRequest::set_access_control_max_age;
	this->_field_name_parser["Access-Control-Request-Headers"] = &HttpRequest::set_access_control_request_headers;
	this->_field_name_parser["Access-Control-Request-Method"] = &HttpRequest::set_access_control_request_method;
	this->_field_name_parser["Age"] = &HttpRequest::set_age;
	this->_field_name_parser["Allow"] = &HttpRequest::set_allow;
	this->_field_name_parser["Alt-Svc"] = &HttpRequest::set_alt_svc;
	this->_field_name_parser["Alt-Used"] = &HttpRequest::set_alt_used;
	this->_field_name_parser["Authorization"] = &HttpRequest::set_authorization;
	this->_field_name_parser["Cache-Control"] =  &HttpRequest::set_cache_control;
	this->_field_name_parser["Clear-Site-Data"] = &HttpRequest::set_clear_site_data;
	this->_field_name_parser["Connection"] = &HttpRequest::set_connection;
	this->_field_name_parser["Content-Disposition"] = &HttpRequest::set_content_disponesition;
	this->_field_name_parser["Content-Encoding"] = &HttpRequest::set_content_encoding;
	this->_field_name_parser["Content-Language"] = &HttpRequest::set_content_language;
	this->_field_name_parser["Content-Length"] = &HttpRequest::set_content_length;
	this->_field_name_parser["Content-Location"] = &HttpRequest::set_content_location;
	this->_field_name_parser["Content-Range"] = &HttpRequest::set_content_range;
	this->_field_name_parser["Content-Security-Policy"] = &HttpRequest::set_content_security_policy;
	this->_field_name_parser["Content-Security-Policy-Report-Only"] = &HttpRequest::set_content_security_policy_report_only;
	this->_field_name_parser["Content-Type"] = &HttpRequest::set_content_type;
	this->_field_name_parser["Cookie"] = &HttpRequest::set_cookie;
	this->_field_name_parser["Cross-Origin-Embedder-Policy"] = &HttpRequest::set_cross_origin_embedder_policy;
	this->_field_name_parser["Cross-Origin-Opener-Policy"] = &HttpRequest::set_cross_origin_opener_policy;
	this->_field_name_parser["Cross-Origin-Resource-Policy"] = &HttpRequest::set_cross_origin_resource_policy;
	this->_field_name_parser["Date"] = &HttpRequest::set_date;
	this->_field_name_parser["ETag"] = &HttpRequest::set_etag;
	this->_field_name_parser["Expect"] = &HttpRequest::set_expect;
	// this->_field_name_parser["Expect-CT"] = this->set_expect_ct;
	this->_field_name_parser["Expires"] = &HttpRequest::set_expires;
	this->_field_name_parser["Forwarded"] = &HttpRequest::set_forwarded;
	this->_field_name_parser["From"] = &HttpRequest::set_from;
	this->_field_name_parser["Host"] = &HttpRequest::set_host;
	this->_field_name_parser["If-Match"] = &HttpRequest::set_if_match;
	this->_field_name_parser["If-Modified-Since"] = &HttpRequest::set_if_modified_since;
	this->_field_name_parser["If-None-Match"] = &HttpRequest::set_if_none_match;
	this->_field_name_parser["If-Range"] = &HttpRequest::set_if_range;
	this->_field_name_parser["If-Unmodified-Since"] = &HttpRequest::set_if_unmodified_since;
	this->_field_name_parser["Keep-Alive"] = &HttpRequest::set_keep_alive;
	this->_field_name_parser["Last-Modified"] = &HttpRequest::set_last_modified;
	this->_field_name_parser["Link"] = &HttpRequest::set_link;
	this->_field_name_parser["Location"] = &HttpRequest::set_location;
	this->_field_name_parser["Max-Forwards"] = &HttpRequest::set_max_forwards;
	this->_field_name_parser["Origin"] = &HttpRequest::set_origin;
	this->_field_name_parser["Permission-Policy"] = &HttpRequest::set_permission_policy;
	this->_field_name_parser["Proxy-Authenticate"] = &HttpRequest::set_proxy_authenticate;
	this->_field_name_parser["Proxy-Authorization"] = &HttpRequest::set_proxy_authorization;
	// this->_field_name_parser["Range"] = this->set_range;
	this->_field_name_parser["Referer"] = &HttpRequest::set_referer;
	this->_field_name_parser["Retry-After"] = &HttpRequest::set_retry_after;
	this->_field_name_parser["Sec-Fetch-Dest"] = &HttpRequest::set_sec_fetch_dest;
	this->_field_name_parser["Sec-Fetch-Mode"] = &HttpRequest::set_sec_fetch_mode;
	this->_field_name_parser["Sec-Fetch-Site"] = &HttpRequest::set_sec_fetch_site;
	this->_field_name_parser["Sec-Fetch-User"] = &HttpRequest::set_sec_fetch_user;
	this->_field_name_parser["Sec-Purpose"] = &HttpRequest::set_sec_purpose;
	this->_field_name_parser["Sec-WebSocket-Accept"] = &HttpRequest::set_sec_websocket_accept;
	this->_field_name_parser["Server"] = &HttpRequest::set_server;
	// this->_field_name_parser["Server-Timing"] = this->set_server_timing;
	this->_field_name_parser["Service-Worker-Navigation-Preload"] = &HttpRequest::set_service_worker_navigation_preload;
	this->_field_name_parser["Set-Cookie"] = &HttpRequest::set_cookie;
	this->_field_name_parser["SourceMap"] = &HttpRequest::set_sourcemap;
	this->_field_name_parser["Strict-Transport-Security"] = &HttpRequest::set_strict_transport_security;
	this->_field_name_parser["TE"] = &HttpRequest::set_te;
	this->_field_name_parser["Timing-Allow-Origin"] = &HttpRequest::set_timing_allow_origin;
	this->_field_name_parser["Trailer"] = &HttpRequest::set_trailer;
	this->_field_name_parser["Transfer-Encoding"] = &HttpRequest::set_transfer_encoding;
	this->_field_name_parser["Upgrade"] = &HttpRequest::set_upgrade;
	this->_field_name_parser["Upgrade-Insecure-Requests"] = &HttpRequest::set_upgrade_insecure_requests;
	this->_field_name_parser["User-Agent"] = &HttpRequest::set_user_agent;
	this->_field_name_parser["Vary"] = &HttpRequest::set_vary;
	this->_field_name_parser["Via"] = &HttpRequest::set_via;
	this->_field_name_parser["WWW-Authenticate"] = &HttpRequest::set_www_authenticate;
	// this->_field_name_parser["X-Custom-Header"] = &HttpRequest::set_x_custom_header;
}

RequestLine& HttpRequest::get_request_line()
{
	return (this->_request_line);
}

BaseKeyValueMap* HttpRequest::return_value(const std::string &key)
{
	return (this->_request_keyvalue_map[key]);
}

std::map<std::string, BaseKeyValueMap*> HttpRequest::get_request_keyvalue_map(void)
{
	return (this->_request_keyvalue_map);
}

int	HttpRequest::get_statuscode() const
{
	return (this->_status_code);
}
