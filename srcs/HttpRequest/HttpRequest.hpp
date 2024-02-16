#pragma once

# include <map>
# include <set>
# include <string>
# include <sstream>
# include <vector>
# include "ConfigStruct.hpp"
# include "Date.hpp"
# include "FieldValueBase.hpp"
# include "MapFieldValues.hpp"
# include "MultiFieldValues.hpp"
# include "RequestLine.hpp"
# include "Result.hpp"
# include "SingleFieldValue.hpp"

class HttpRequest {
 public:
	HttpRequest();
	explicit HttpRequest(const std::string &input);
	~HttpRequest();

	int get_status_code() const;
	std::string	get_method() const;
	std::string get_request_target() const;
	std::string	get_http_version() const;

    Result<int, std::string> recv_all_data(int fd);
    Result<int, std::string> parse_request_line();
    Result<int, std::string> parse_request_header();
    Result<int, std::string> parse_request_body(std::size_t max_body_size);
    Result<HostPortPair, int> get_server_info();

	bool is_field_name_supported_parsing(const std::string &field_name);
	bool is_valid_field_name_registered(const std::string &field_name);
	bool is_field_name_repeated_in_request(const std::string &field_name);

	std::map<std::string, FieldValueBase*> get_request_header_fields(void);
	FieldValueBase * get_field_values(const std::string &field_name) const;

    Result<std::map<std::string, std::string>, int> get_host() const;

#ifdef UTEST
    friend class HttpRequestFriend;
#endif

 private:
	int status_code_;
	RequestLine request_line_;
	std::map<std::string, FieldValueBase *> request_header_fields_;
	std::string message_body_;
    std::vector<unsigned char> request_body_;
    std::vector<unsigned char> data_;
    std::vector<unsigned char>::const_iterator data_begin_;

	typedef Result<int, int> (HttpRequest::*func_ptr)(const std::string&, const std::string&);
	std::map<std::string, func_ptr> field_value_parser_;
	std::map<std::string, int> field_name_counter_;

	HttpRequest(const HttpRequest &other);
	HttpRequest &operator=(const HttpRequest &rhs);

	/* parse, validate */
    static Result<std::string, std::string> get_line(const std::vector<unsigned char> &data,
                                                     std::vector<unsigned char>::const_iterator start,
                                                     std::vector<unsigned char>::const_iterator *ret);
    static void find_crlf(const std::vector<unsigned char> &data,
                          std::vector<unsigned char>::const_iterator start,
                          std::vector<unsigned char>::const_iterator *cr);
    static void find_empty(const std::vector<unsigned char> &data,
                           std::vector<unsigned char>::const_iterator start,
                           std::vector<unsigned char>::const_iterator *ret);

	int parse_and_validate_http_request(const std::string &input);
	Result<int, int> parse_and_validate_field_lines(std::stringstream *ss);
	Result<int, int> parse_field_line(const std::string &field_line,
									  std::string *ret_field_name,
									  std::string *ret_field_value);
	std::string parse_message_body(std::stringstream *ss);

	/* operator */
	void increment_field_name_counter(const std::string &field_name);
	void init_field_name_counter();
	void init_field_name_parser(void);

	void clear_field_values_of(const std::string &field_name);

	/* set data */
	Result<int, int> set_multi_field_values(const std::string &field_name,
											const std::string &field_value,
											bool (*syntax_validate_func)(const std::string &));
	Result<int, int> set_valid_http_date(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_valid_media_type(const std::string &field_name, const std::string &field_value);

	/* parse func */
	Result<int, int> set_accept(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_accept_encoding(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_accept_language(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_access_control_request_headers(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_access_control_request_method(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_alt_used(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_authorization(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_cache_control(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_connection(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_disposition(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_encoding(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_language(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_length(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_location(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_content_type(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_cookie(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_date(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_expect(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_forwarded(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_from(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_host(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_if_match(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_if_modified_since(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_if_none_match(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_if_range(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_if_unmodified_since(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_keep_alive(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_last_modified(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_link(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_max_forwards(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_origin(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_proxy_authorization(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_range(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_referer(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_sec_fetch_dest(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_sec_fetch_mode(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_sec_fetch_site(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_sec_fetch_user(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_sec_purpose(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_service_worker_navigation_preload(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_te(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_trailer(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_transfer_encoding(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_upgrade(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_upgrade_insecure_requests(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_user_agent(const std::string &field_name, const std::string &field_value);
	Result<int, int> set_via(const std::string &field_name, const std::string &field_value);
};
