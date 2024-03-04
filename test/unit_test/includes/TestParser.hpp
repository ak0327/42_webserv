#pragma once

#include <list>
#include <vector>
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Tokenizer.hpp"
#include "ConfigParser.hpp"
#include "gtest/gtest.h"


void expect_eq_return(const ReturnDirective &expected,
                      const ReturnDirective &actual,
                      const std::size_t line);


void expect_eq_listen(const ListenDirective &expected,
                      const ListenDirective &actual,
                      const std::size_t line);

void expect_eq_listens(const std::vector<ListenDirective> &expected,
                       const std::vector<ListenDirective> &actual,
                       const std::size_t line);


void expect_eq_limit_except(const LimitExceptDirective &expected,
                            const LimitExceptDirective &actual,
                            const std::size_t line);


void expect_eq_default_config(const DefaultConfig &expected,
                              const DefaultConfig &actual,
                              const std::size_t line);


void expect_eq_location_config(const LocationConfig &expected,
                               const LocationConfig &actual,
                               const std::size_t line);


void expect_eq_server_config(const ServerConfig &expected,
                             const ServerConfig &actual,
                             const std::size_t line);

void expect_eq_http_config(const HttpConfig &expected,
                           const HttpConfig &actual,
                           const std::size_t line);


void expect_eq_locations(const std::map<std::string, LocationConfig> &expected,
                         const std::map<std::string, LocationConfig> &actual,
                         const std::size_t line);


std::set<std::string> get_conf_files(const std::string &directory_path);


template <typename OkType>
void print_error_msg(Result<OkType, std::string> result, const std::size_t line);

void debug_print(const std::string &msg, const std::size_t line);

class ConfigParserTestFriend : public ::testing::Test {
 public:
    static Result<int, std::string> parse_directive_param(TokenItr *current,
                                                          const TokenItr end,
                                                          std::string *param,
                                                          const std::string &directive_name) {
        return ConfigParser::parse_directive_param(current, end, param, directive_name);
    }


    static Result<int, std::string> parse_directive_params(TokenItr *current,
                                                           const TokenItr end,
                                                           std::vector<std::string> *params,
                                                           const std::string &directive_name) {
        return ConfigParser::parse_directive_params(current, end, params, directive_name);
    }


    static Result<int, std::string> parse_set_params(TokenItr *current,
                                                     const TokenItr end,
                                                     std::set<std::string> *params,
                                                     const std::string &name) {
        return ConfigParser::parse_set_params(current, end, params, name);
    }


    static Result<AddressPortPair, int> parse_listen_param(const std::string &param) {
        return ConfigParser::parse_listen_param(param);
    }


    static Result<int, std::string> parse_listen_directive(TokenItr *current,
                                                           const TokenItr end,
                                                           std::vector<ListenDirective> *listen_directives) {
        return ConfigParser::parse_listen_directive(current, end, listen_directives);
    }


    static Result<int, std::string> parse_return_directive(TokenItr *current,
                                                           const TokenItr end,
                                                           ReturnDirective *redirection) {
        return ConfigParser::parse_return_directive(current, end, redirection);
    }


    static Result<int, std::string> parse_root_directive(TokenItr *current,
                                                         const TokenItr end,
                                                         std::string *root_path) {
        return ConfigParser::parse_root_directive(current, end, root_path);
    }


    static Result<int, std::string> parse_limit_except_directive(TokenItr *current,
                                                                 const TokenItr end,
                                                                 LimitExceptDirective *limit_except) {
        return ConfigParser::parse_limit_except_directive(current, end, limit_except);
    }


    static Result<int, std::string> parse_error_page_directive(TokenItr *current,
                                                               const TokenItr end,
                                                               std::map<StatusCode, std::string> *error_pages) {
        return ConfigParser::parse_error_page_directive(current, end, error_pages);
    }


    static Result<int, std::string> parse_autoindex_directive(TokenItr *current,
                                                              const TokenItr end,
                                                              bool *autoindex) {
        return ConfigParser::parse_autoindex_directive(current, end, autoindex);
    }


    static Result<int, std::string> parse_body_size_directive(TokenItr *current,
                                                              const TokenItr end,
                                                              std::size_t *max_body_size_bytes) {
        return ConfigParser::parse_body_size_directive(current, end, max_body_size_bytes);
    }


    static Result<int, std::string> parse_default_config(TokenItr *current,
                                                         const TokenItr end,
                                                         DefaultConfig *default_config) {
        return ConfigParser::parse_default_config(current, end, default_config);
    }

    static Result<std::string, std::string> parse_location_path(TokenItr *current,
                                                                const TokenItr end) {
        return ConfigParser::parse_location_path(current, end);
    }

    static Result<int, std::string> parse_location_block(TokenItr *current,
                                                         const TokenItr end,
                                                         LocationConfig *location_config) {
        return ConfigParser::parse_location_block(current, end, location_config);
    }


    static Result<int, std::string> parse_server_block(TokenItr *current,
                                                       const TokenItr end,
                                                       ServerConfig *server_config) {
        return ConfigParser::parse_server_block(current, end, server_config);
    }

    static Result<int, std::string> parse_cgi_mode_directive(TokenItr *current,
                                                             const TokenItr &end,
                                                             bool *cgi_mode) {
        return ConfigParser::parse_cgi_mode_directive(current, end, cgi_mode);
    }

    static Result<int, std::string> parse_timeout_directive(TokenItr *current,
                                                                const TokenItr &end,
                                                                time_t *timeout_sec,
                                                                const std::string &directive_name,
                                                                bool (*validate_func)(time_t)) {
        return ConfigParser::parse_timeout_directive(current, end, timeout_sec, directive_name, validate_func);
    }

};
