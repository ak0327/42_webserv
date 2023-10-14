#pragma once

# include <map>
# include <set>
# include <string>
# include <sstream>
# include <vector>

# include "FieldValues.hpp"
# include "StringHandler.hpp"
# include "RequestLine.hpp"
# include "ValueWeightArraySet.hpp"
# include "MultiFieldValues.hpp"
# include "SingleFieldValue.hpp"
# include "TwoValueSet.hpp"
# include "FieldValueMap.hpp"
# include "Date.hpp"
# include "LinkClass.hpp"
# include "Result.hpp"

class FieldValues;
class RequestLine;
class TwoValueSet;
class MultiFieldValues;
class Date;
class FieldValueMap;
class SingleFieldValue;
class ValueWeightArraySet;

class HttpRequest {
 public:
	explicit HttpRequest(const std::string &input);
	~HttpRequest();

	bool is_accept_langage_valueword(const std::string &value);

	int get_status_code() const;
	std::string	get_method() const;
	std::string get_request_target() const;
	std::string	get_http_version() const;

	bool is_valid_field_name_registered(const std::string &field_name);
	bool has_multiple_field_names(const std::string &field_name);
	std::map<std::string, FieldValues*> get_request_header_fields(void);
	FieldValues *get_field_values(const std::string &field_name);

 private:
	int _status_code;
	RequestLine _request_line;
	std::map<std::string, FieldValues*> _request_header_fields;
	std::string _message_body;

	typedef Result<int, int> (HttpRequest::*func_ptr)(const std::string&, const std::string&);
	std::map<std::string, func_ptr> _field_value_parser;
	std::map<std::string, int> _field_name_counter;

	HttpRequest();
	HttpRequest(const HttpRequest &request);
	const HttpRequest &operator=(const HttpRequest &rhs);

	/* parse, validate */
	int parse_and_validate_http_request(const std::string &input);
	Result<int, int> parse_and_validate_field_lines(std::stringstream *ss);

	Result<int, int> parse_field_line(const std::string &field_line,
									  std::string *ret_field_name,
									  std::string *ret_field_value);
	std::string parse_message_body(std::stringstream *ss);

	bool is_valid_field_name_syntax(const std::string &field_name);
	bool is_valid_field_value_syntax(const std::string &field_value);
	bool is_valid_field_name(const std::string &field_name);

	void clear_field_values_of(const std::string &field_name);

	Result<int, int> set_valid_http_date(const std::string &field_name,
										 const std::string &field_value);
	Result<int, int> set_valid_media_type(const std::string &field_name,
										  const std::string &field_value);

	void increment_field_name_counter(const std::string &field_name);

	bool is_weightformat(const std::string &value);
	LinkClass *ready_LinkClass(std::map<std::string, std::map<std::string, std::string> > link_valuemap);
	std::map<std::string, std::string> ready_mappingvalue(const std::string &value_map);
	std::vector<std::string> securitypolicy_readyvector(const std::string &words);
	TwoValueSet *ready_TwoValueSet(const std::string &value);
	TwoValueSet *ready_TwoValueSet(const std::string &value, char delimiter);
	MultiFieldValues *ready_ValueArraySet(const std::string &value);
	Date *ready_ValueDateSet(const std::string &value);
	FieldValueMap *ready_ValueMap(const std::string &value);
	FieldValueMap *ready_ValueMap(const std::string &value, char delimiter);
	FieldValueMap *ready_ValueMap(const std::string &only_value, const std::string &value);
	SingleFieldValue *ready_ValueSet(const std::string &value);
	ValueWeightArraySet*ready_ValueWeightArraySet(const std::string &value);

	void init_field_name_counter();
	void init_field_name_parser(void);

	Result<int, int> set_multi_field_values(const std::string &field_name,
											const std::string &field_value,
											bool (*is_valid_syntax)(const std::string &));

	Result<int, int> set_accept(const std::string &key, const std::string &value);
	Result<int, int> set_accept_charset(const std::string &key, const std::string &value);
	Result<int, int> set_accept_encoding(const std::string &key, const std::string &value);
	Result<int, int> set_accept_language(const std::string &key, const std::string &value);
	Result<int, int> set_access_control_request_headers(const std::string &key, const std::string &value);
	Result<int, int> set_access_control_request_method(const std::string &key, const std::string &value);
	Result<int, int> set_alt_used(const std::string &key, const std::string &value);
	Result<int, int> set_authorization(const std::string &key, const std::string &value);
	Result<int, int> set_connection(const std::string &key, const std::string &value);
	Result<int, int> set_content_disponesition(const std::string &key, const std::string &value);
	Result<int, int> set_content_encoding(const std::string &key, const std::string &value);
	Result<int, int> set_content_language(const std::string &key, const std::string &value);

	Result<int, int> set_content_length(const std::string &field_name,
										const std::string &field_value);

	Result<int, int> set_content_location(const std::string &key, const std::string &value);
	Result<int, int> set_content_range(const std::string &key, const std::string &value);
	Result<int, int> set_content_type(const std::string &key, const std::string &value);
	Result<int, int> set_cookie(const std::string &key, const std::string &value);
	Result<int, int> set_date(const std::string &key, const std::string &value);
	Result<int, int> set_expect(const std::string &key, const std::string &value);
	Result<int, int> set_expires(const std::string &key, const std::string &value);
	Result<int, int> set_forwarded(const std::string &key, const std::string &value);
	Result<int, int> set_email(const std::string &key, const std::string &value);
	Result<int, int> set_from(const std::string &key, const std::string &value);
	Result<int, int> set_host(const std::string &key, const std::string &value);
	Result<int, int> set_if_match(const std::string &key, const std::string &value);
	Result<int, int> set_if_modified_since(const std::string &key, const std::string &value);
	Result<int, int> set_if_none_match(const std::string &key, const std::string &value);
	Result<int, int> set_if_range(const std::string &key, const std::string &value);
	Result<int, int> set_if_unmodified_since(const std::string &key, const std::string &value);
	Result<int, int> set_keep_alive(const std::string &key, const std::string &value);
	Result<int, int> set_last_modified(const std::string &key, const std::string &value);
	Result<int, int> set_link(const std::string &key, const std::string &value);
	Result<int, int> set_location(const std::string &key, const std::string &value);
	Result<int, int> set_max_forwards(const std::string &key, const std::string &value);
	Result<int, int> set_origin(const std::string &key, const std::string &value);
	Result<int, int> set_permission_policy(const std::string &key, const std::string &value);
	Result<int, int> set_proxy_authenticate(const std::string &key, const std::string &value);
	Result<int, int> set_proxy_authorization(const std::string &key, const std::string &value);
	Result<int, int> set_referer(const std::string &key, const std::string &value);
	Result<int, int> set_retry_after(const std::string &key, const std::string &value);
	Result<int, int> set_sec_fetch_dest(const std::string &key, const std::string &value);
	Result<int, int> set_sec_fetch_mode(const std::string &key, const std::string &value);
	Result<int, int> set_sec_fetch_site(const std::string &key, const std::string &value);
	Result<int, int> set_sec_fetch_user(const std::string &key, const std::string &value);
	Result<int, int> set_sec_purpose(const std::string &key, const std::string &value);
	Result<int, int> set_sec_websocket_accept(const std::string &key, const std::string &value);
	Result<int, int> set_server(const std::string &key, const std::string &value);
	Result<int, int> set_service_worker_navigation_preload(const std::string &key, const std::string &value);
	Result<int, int> set_set_cookie(const std::string &key, const std::string &value);
	Result<int, int> set_sourcemap(const std::string &key, const std::string &value);
	Result<int, int> set_strict_transport_security(const std::string &key, const std::string &value);
	Result<int, int> set_te(const std::string &key, const std::string &value);
	Result<int, int> set_timing_allow_origin(const std::string &key, const std::string &value);
	Result<int, int> set_trailer(const std::string &key, const std::string &value);
	Result<int, int> set_transfer_encoding(const std::string &key, const std::string &value);
	Result<int, int> set_upgrade(const std::string &key, const std::string &value);
	Result<int, int> set_upgrade_insecure_requests(const std::string &key, const std::string &value);
	Result<int, int> set_user_agent(const std::string &key, const std::string &value);
	Result<int, int> set_vary(const std::string &key, const std::string &value);
	Result<int, int> set_via(const std::string &key, const std::string &value);
	Result<int, int> set_www_authenticate(const std::string &key, const std::string &value);
};
