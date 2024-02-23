#pragma once

# include <deque>
# include <map>
# include <set>
# include <string>
# include <vector>
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Token.hpp"
# include "Result.hpp"


typedef std::deque<Token>::const_iterator TokenItr;
typedef std::map<LocationPath, TokenItr> LocationItrMap;

class ConfigParser {
 public:
	ConfigParser();
	explicit ConfigParser(const char *file_path);
	ConfigParser(const ConfigParser &other);
	~ConfigParser();

	ConfigParser &operator=(const ConfigParser &rhs);

	Result<int, std::string> result() const;
	HttpConfig config() const;

#ifdef UNIT_TEST
	friend class ConfigParserTestFriend;
#endif

 private:
	HttpConfig http_config_;
	Result<int, std::string> result_;

	static Result<HttpConfig, std::string> parse(const std::deque<Token> &tokens);
	static Result<int, std::string> validate(const HttpConfig &http_config);
    void fill_unspecified_directives(HttpConfig *http_config);
	void fill_unspecified_listen(HttpConfig *http_config);
	void fill_unspecified_server_name(HttpConfig *http_config);

	// Recursive descent parse func
    static bool is_at_end(TokenItr *current, const TokenItr &end);
    static bool consume(TokenItr *current, const TokenItr &end, const std::string &expected_str);
    static bool consume(TokenItr *current, const TokenItr &end, TokenKind expected_kind);
    static bool expect(TokenItr *current, const TokenItr &end, const std::string &expected_str);
    static bool expect(TokenItr *current, const TokenItr &end, TokenKind expected_kind);
    static void skip_comments(TokenItr *current, const TokenItr &end);

	// parse block
    static Result<int, std::string> parse_http_block(TokenItr *current,
                                                     const TokenItr &end,
                                                     HttpConfig *http_config);

    static Result<int, std::string> parse_server_block(TokenItr *current,
                                                       const TokenItr &end,
                                                       ServerConfig *server_config);

    static Result<int, std::string> skip_location(TokenItr *current,
                                                  const TokenItr &end,
                                                  LocationItrMap *location_iterators);


    static Result<int, std::string> parse_location(const LocationItrMap &location_iterators,
                                                   const LocationConfig &init_config,
                                                   const TokenItr &end,
                                                   std::map<LocationPath, LocationConfig> *locations);


    static Result<int, std::string> parse_location_block(TokenItr *current,
                                                         const TokenItr &end,
                                                         LocationConfig *location_config);

	static Result<std::string, std::string> parse_location_path(TokenItr *current,
                                                                const TokenItr &end);

    static Result<int, std::string> parse_default_config(TokenItr *current,
                                                         const TokenItr &end,
                                                         DefaultConfig *default_config);

	static Result<int, std::string> skip_events_block(TokenItr *current,
                                                      const TokenItr &end);


	// parse directive
	static Result<int, std::string> parse_directive_param(TokenItr *current,
                                                          const TokenItr &end,
                                                          std::string *param,
                                                          const std::string &directive_name);

	static Result<int, std::string> parse_directive_params(TokenItr *current,
                                                           const TokenItr &end,
                                                           std::vector<std::string> *params,
                                                           const std::string &directive_name);

	static Result<int, std::string> parse_set_params(TokenItr *current,
                                                     const TokenItr &end,
                                                     std::set<std::string> *params,
                                                     const std::string &name);

	static Result<int, std::string> parse_listen_directive(TokenItr *current,
                                                           const TokenItr &end,
                                                           std::vector<ListenDirective> *listen_directives);

    static Result<int, std::string> parse_return_directive(TokenItr *current,
                                                           const TokenItr &end,
                                                           ReturnDirective *redirection);

    static Result<int, std::string> parse_root_directive(TokenItr *current,
                                                         const TokenItr &end,
                                                         std::string *root_path);

    static Result<int, std::string> parse_limit_except_directive(TokenItr *current,
                                                                 const TokenItr &end,
                                                                 LimitExceptDirective *limit_except);

	static Result<int, std::string> parse_access_rule(TokenItr *current,
                                                      const TokenItr &end,
                                                      std::vector<AccessRule> *rules,
                                                      const std::string &name);

    static Result<int, std::string> parse_error_page_directive(TokenItr *current,
                                                               const TokenItr &end,
                                                               std::map<StatusCode, std::string> *error_pages);

    static Result<int, std::string> parse_autoindex_directive(TokenItr *current,
                                                              const TokenItr &end,
                                                              bool *autoindex);

    static Result<int, std::string> parse_body_size_directive(TokenItr *current,
                                                              const TokenItr &end,
                                                              std::size_t *max_body_size_bytes);

	// mv to utility ?
	static bool is_valid_error_code(int error_code);
	static bool is_valid_return_code(int return_code);
	static bool is_access_rule_directive(TokenItr *current, const TokenItr &end);
	static Result<Method, std::string> get_method(const std::string &method);
	static Result<AddressPortPair, int> parse_listen_param(const std::string &param);
	static Result<std::size_t, int> parse_size_with_prefix(const std::string &size_str);

	// error message
	static std::string create_syntax_err_msg(const TokenItr &current,
											 const TokenItr &end,
											 const std::string &expecting);

	static std::string create_syntax_err_msg(const TokenItr &current,
											 const TokenItr &end);

	static std::string create_invalid_value_err_msg(const TokenItr &current,
													const TokenItr &end);

	static std::string create_invalid_value_err_msg(const TokenItr &current,
													const TokenItr &end,
													const std::string &directive_name);

	static std::string create_invalid_value_err_msg(const std::string &invalid_value,
													const std::string &directive_name);

	static std::string create_invalid_num_of_arg_err_msg(const TokenItr &current,
														 const TokenItr &end,
														 const std::string &directive_name);
	static std::string create_duplicated_directive_err_msg(const TokenItr &current,
												           const TokenItr &end,
												           const std::string &directive_name);
	static std::string create_duplicated_location_err_msg(const TokenItr &current,
														  const TokenItr &end,
														  const std::string &directive_name);
	static std::string create_recursive_location_err_msg(const TokenItr &current,
														 const TokenItr &end,
														 const std::string &outside);
};
