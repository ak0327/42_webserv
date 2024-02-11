#pragma once

# include <deque>
# include <map>
# include <string>
# include <vector>
# include "ConfigStruct.hpp"
# include "Token.hpp"
# include "Result.hpp"


typedef std::deque<Token>::const_iterator TokenConstItr;

class Parser {
 public:
	Parser();
	explicit Parser(const char *file_path);
	Parser(const Parser &other);
	~Parser();

	Parser &operator=(const Parser &rhs);

	Result<int, std::string> get_result() const;
	HttpConfig get_config() const;

#ifdef UTEST
	friend class ParserTestFriend;
#endif

 private:
	HttpConfig http_config_;
	Result<int, std::string> result_;

	static Result<HttpConfig, std::string> parse(const std::deque<Token> &tokens);
	static Result<int, std::string> validate(const HttpConfig &http_config);
	void set_default_listen(HttpConfig &http_config);
	void set_default_server_name(HttpConfig &http_config);
	void set_default_server();

	// Recursive descent parse func
    static bool is_at_end(TokenConstItr *current, const TokenConstItr end);
    static bool consume(TokenConstItr *current, const TokenConstItr end, const std::string &expected_str);
    static bool consume(TokenConstItr *current, const TokenConstItr end, TokenKind expected_kind);
    static bool expect(TokenConstItr *current, const TokenConstItr end, const std::string &expected_str);
    static bool expect(TokenConstItr *current, const TokenConstItr end, TokenKind expected_kind);
    static void skip_comments(TokenConstItr *current, const TokenConstItr end);

	// parse block
    static Result<int, std::string> parse_http_block(TokenConstItr *current,
                                                     const TokenConstItr end,
                                                     HttpConfig *http_config);

    static Result<int, std::string> parse_server_block(TokenConstItr *current,
                                                       const TokenConstItr end,
                                                       ServerConfig *server_config);

    static Result<int, std::string> parse_location(TokenConstItr *current,
                                                   const TokenConstItr end,
                                                   std::map<std::string, LocationConfig> *locations);

    static Result<int, std::string> parse_location_block(TokenConstItr *current,
                                                         const TokenConstItr end,
                                                         LocationConfig *location_config);

	static Result<std::string, std::string> parse_location_path(TokenConstItr *current,
																const TokenConstItr end);

    static Result<int, std::string> parse_default_config(TokenConstItr *current,
                                                         const TokenConstItr end,
                                                         DefaultConfig *default_config);

	static Result<int, std::string> skip_events_block(TokenConstItr *current,
													  const TokenConstItr end);


	// parse directive
	static Result<int, std::string> parse_directive_param(TokenConstItr *current,
														  const TokenConstItr end,
														  std::string *param,
														  const std::string &directive_name);

	static Result<int, std::string> parse_directive_params(TokenConstItr *current,
                                                           const TokenConstItr end,
                                                           std::vector<std::string> *params,
                                                           const std::string &directive_name);

	static Result<int, std::string> parse_set_params(TokenConstItr *current,
		                                             const TokenConstItr end,
		                                             std::set<std::string> *params,
		                                             const std::string &name);

	static Result<int, std::string> parse_listen_directive(TokenConstItr *current,
                                                           const TokenConstItr end,
                                                           std::vector<ListenDirective> *listen_directives);

    static Result<int, std::string> parse_return_directive(TokenConstItr *current,
                                                           const TokenConstItr end,
                                                           ReturnDirective *redirection);

    static Result<int, std::string> parse_root_directive(TokenConstItr *current,
                                                         const TokenConstItr end,
                                                         std::string *root_path);

    static Result<int, std::string> parse_limit_except_directive(TokenConstItr *current,
                                                                 const TokenConstItr end,
                                                                 LimitExceptDirective *limit_except);

	static Result<int, std::string> parse_access_rule(TokenConstItr *current,
													  const TokenConstItr end,
													  std::vector<AccessRule> *rules,
													  const std::string &name);

    static Result<int, std::string> parse_error_page_directive(TokenConstItr *current,
                                                               const TokenConstItr end,
                                                               std::map<StatusCode, std::string> *error_pages);

    static Result<int, std::string> parse_autoindex_directive(TokenConstItr *current,
                                                              const TokenConstItr end,
                                                              bool *autoindex);

    static Result<int, std::string> parse_body_size_directive(TokenConstItr *current,
                                                              const TokenConstItr end,
                                                              std::size_t *max_body_size_bytes);

	// mv to utility ?
	static bool is_valid_error_code(StatusCode code);
	static bool is_valid_return_code(StatusCode code);
	static bool is_access_rule_directive(TokenConstItr *current, const TokenConstItr end);
	static Result<Method, std::string> get_method(const std::string &method);
	static Result<AddressPortPair, int> parse_listen_param(const std::string &param);
	static Result<std::size_t, int> parse_size_with_prefix(const std::string &size_str);

	// error message
	static std::string create_syntax_err_msg(const TokenConstItr current,
											 const TokenConstItr end,
											 const std::string &expecting);

	static std::string create_syntax_err_msg(const TokenConstItr current,
											 const  TokenConstItr end);

	static std::string create_invalid_value_err_msg(const TokenConstItr current,
													const TokenConstItr end);

	static std::string create_invalid_value_err_msg(const TokenConstItr current,
													const TokenConstItr end,
													const std::string &directive_name);

	static std::string create_invalid_value_err_msg(const std::string &invalid_value,
													const std::string &directive_name);

	static std::string create_invalid_num_of_arg_err_msg(const TokenConstItr current,
														 const TokenConstItr end,
														 const std::string &directive_name);
	static std::string create_duplicated_directive_err_msg(const TokenConstItr current,
												           const TokenConstItr end,
												           const std::string &directive_name);
	static std::string create_duplicated_location_err_msg(const TokenConstItr current,
														  const TokenConstItr end,
														  const std::string &directive_name);
	static std::string create_recursive_location_err_msg(const TokenConstItr current,
														 const TokenConstItr end,
														 const std::string &outside);
};
