#pragma once

#include <list>
#include <vector>
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Tokenizer.hpp"
#include "Parser.hpp"
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

template <typename OkType>
void print_error_msg(Result<OkType, std::string> result, const std::size_t line);

void debug_print(const std::string &msg, const std::size_t line);

class ParserTestFriend : public ::testing::Test {
 public:
    static Result<int, std::string> parse_directive_param(TokenConstItr &current,
                                                          const TokenConstItr end,
                                                          std::string &param,
                                                          const std::string &directive_name) {
        return Parser::parse_directive_param(current, end, param, directive_name);
    }


    static Result<int, std::string> parse_directive_params(TokenConstItr &current,
                                                           const TokenConstItr end,
                                                           std::vector<std::string> &params,
                                                           const std::string &directive_name) {
        return Parser::parse_directive_params(current, end, params, directive_name);
    }


    static Result<int, std::string> parse_set_params(TokenConstItr &current,
                                                 const TokenConstItr end,
                                                 std::set<std::string> &params,
                                                 const std::string &name) {
        return Parser::parse_set_params(current, end, params, name);
    }


    static Result<AddressPortPair, int> parse_listen_param(const std::string &param) {
        return Parser::parse_listen_param(param);
    }


    static Result<int, std::string> parse_listen_directive(TokenConstItr &current,
                                                           const TokenConstItr end,
                                                           std::vector<ListenDirective> &listen_directives) {
        return Parser::parse_listen_directive(current, end, listen_directives);
    }


    static Result<int, std::string> parse_return_directive(TokenConstItr &current,
                                                          const TokenConstItr end,
                                                          ReturnDirective &redirection) {
        return Parser::parse_return_directive(current, end, redirection);
    }


    static Result<int, std::string> parse_root_directive(TokenConstItr &current,
                                                         const TokenConstItr end,
                                                         std::string &root_path) {
        return Parser::parse_root_directive(current, end, root_path);
    }


    static Result<int, std::string> parse_limit_except_directive(TokenConstItr &current,
                                                             const TokenConstItr end,
                                                             LimitExceptDirective &limit_except) {
        return Parser::parse_limit_except_directive(current, end, limit_except);
    }


    static Result<int, std::string> parse_error_page_directive(TokenConstItr &current,
                                                               const TokenConstItr end,
                                                               std::map<StatusCode, std::string> &error_pages) {
        return Parser::parse_error_page_directive(current, end, error_pages);
    }


    static Result<int, std::string> parse_autoindex_directive(TokenConstItr &current,
                                                          const TokenConstItr end,
                                                          bool &autoindex) {
        return Parser::parse_autoindex_directive(current, end, autoindex);
    }


    static Result<int, std::string> parse_body_size_directive(TokenConstItr &current,
                                                              const TokenConstItr end,
                                                              std::size_t &max_body_size_bytes) {
        return Parser::parse_body_size_directive(current, end, max_body_size_bytes);
    }


    static Result<int, std::string> parse_default_config(TokenConstItr &current,
                                                         const TokenConstItr end,
                                                         DefaultConfig &default_config) {
        return Parser::parse_default_config(current, end, default_config);
    }

    static Result<std::string, std::string> parse_location_path(TokenConstItr &current,
                                                                const TokenConstItr end) {
        return Parser::parse_location_path(current, end);
    }

    static Result<int, std::string> parse_location(TokenConstItr &current,
                                                   const TokenConstItr end,
                                                   std::map<std::string, LocationConfig> &locations) {
        return Parser::parse_location(current, end, locations);
    }


    static Result<int, std::string> parse_server_block(TokenConstItr &current,
                                                       const TokenConstItr end,
                                                       ServerConfig &server_config) {
        return Parser::parse_server_block(current, end, server_config);
    }
};
