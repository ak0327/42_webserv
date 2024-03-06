#include <deque>
#include <limits>
#include <set>
#include <utility>
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "ConfigParser.hpp"
#include "Tokenizer.hpp"
#include "StringHandler.hpp"
#include "HttpMessageParser.hpp"


// "server"  "{"  directive_name ... "}"
// ^current                               ^return
Result<int, std::string> ConfigParser::parse_server_block(TokenItr *current,
                                                          const TokenItr &end,
                                                          ServerConfig *server_config) {
    if (!current || !server_config) {
        return Result<int, std::string>::err("fatal error");
    }

    if (!consume(current, end, SERVER_BLOCK)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, SERVER_BLOCK);
        return Result<int, std::string>::err(error_msg);
    }
    if (!consume(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LEFT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    std::map<LocationPath, TokenItr> location_iterators;
    int session_timeout_cnt = 0;
    int header_timeout_cnt = 0;
    int body_timeout_cnt = 0;
    int send_timeout_cnt = 0;

    while (*current != end) {
        if (consume(current, end, RIGHT_PAREN)) {
            break;
        }

        TokenItr tmp = *current;
        Result<int, std::string> result;
        if (consume(current, end, LISTEN_DIRECTIVE)) {
            result = parse_listen_directive(current, end, &server_config->listens);
        } else if (consume(current, end, SERVER_NAME_DIRECTIVE)) {
            result = parse_set_params(current, end, &server_config->server_names, SERVER_NAME_DIRECTIVE);
        } else if (consume(current, end, SESSION_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&session_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, SESSION_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &server_config->session_timeout_sec,
                                             SESSION_TIMEOUT_DIRECTIVE,
                                             is_valid_session_timeout);

        } else if (consume(current, end, CLIENT_HEADER_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&header_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, CLIENT_HEADER_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &server_config->client_header_timeout_sec,
                                             CLIENT_HEADER_TIMEOUT_DIRECTIVE,
                                             is_valid_client_header_timeout);

        } else if (consume(current, end, CLIENT_BODY_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&body_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, CLIENT_BODY_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &server_config->client_body_timeout_sec,
                                             CLIENT_BODY_TIMEOUT_DIRECTIVE,
                                             is_valid_client_body_timeout);

        } else if (consume(current, end, SEND_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&send_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, SEND_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &server_config->send_timeout_sec,
                                             SEND_TIMEOUT_DIRECTIVE,
                                             is_valid_client_body_timeout);

        } else if (expect(current, end, LOCATION_BLOCK)) {
            result = skip_location(current, end, &location_iterators);
        } else {
            result = parse_default_config(current, end, server_config);
        }

        if (result.is_err()) {
            const std::string error_msg = result.err_value();
            return Result<int, std::string>::err(error_msg);
        }
        if (tmp == *current) {
            const std::string error_msg = create_syntax_err_msg(*current, end);
            return Result<int, std::string>::err(error_msg);
        }
    }

    LocationConfig init_config(*server_config);
    Result<int, std::string> location_result = parse_location(location_iterators,
                                                              init_config,
                                                              end,
                                                              &server_config->locations);
    if (location_result.is_err()) {
        const std::string error_msg = location_result.err_value();
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}


// "listen" ( address[:port] / port ) [default_server]  ";"
//          ^current                                         ^return
Result<int, std::string> ConfigParser::parse_listen_directive(TokenItr *current,
                                                              const TokenItr &end,
                                                              std::vector<ListenDirective> *listen_directives) {
    std::vector<std::string> listen_params;
    ListenDirective listen_directive;
    Result<int, std::string> result;

    if (!current || !listen_directives) {
        return Result<int, std::string>::err("fatal error");
    }

    result = parse_directive_params(current, end, &listen_params, LISTEN_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (listen_params.empty() || 2 < listen_params.size()) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, LISTEN_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }

    std::vector<std::string>::const_iterator param = listen_params.begin();
    Result<AddressPortPair, int> param_result = parse_listen_param(*param);
    if (param_result.is_err()) {
        const std::string error_msg = create_invalid_value_err_msg(*param, LISTEN_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }
    AddressPortPair pair = param_result.ok_value();
    const std::string address = pair.first;
    const std::string port = pair.second;
    if (!address.empty()) {
        listen_directive.address = address;
    }
    if (!port.empty()) {
        listen_directive.port = port;
    }

    ++param;
    if (param != listen_params.end()) {
        if (*param != "default_server") {
            const std::string error_msg = create_invalid_value_err_msg(*current, end, LISTEN_DIRECTIVE);
            return Result<int, std::string>::err(error_msg);
        }
        listen_directive.is_default_server = true;
    }
    listen_directives->push_back(listen_directive);
    return Result<int, std::string>::ok(OK);
}
