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


// "http"  "{"  "server"  "{" ... "}" ... "}"
// ^current                                    ^return
Result<int, std::string> ConfigParser::parse_http_block(TokenItr *current,
                                                        const TokenItr &end,
                                                        HttpConfig *http_config) {
    if (!current || !http_config) {
        return Result<int, std::string>::err("fatal error");
    }

    if (!consume(current, end, HTTP_BLOCK)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, HTTP_BLOCK);
        return Result<int, std::string>::err(error_msg);
    }
    if (!consume(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LEFT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    int recv_timeout_cnt = 0;
    int send_timeout_cnt = 0;
    int keepalive_timeout_cnt = 0;

    while (*current != end) {
        if (expect(current, end, RIGHT_PAREN)) {
            break;
        }
        // if (!expect(current, end, SERVER_BLOCK)) {
        //     break;
        // }
        // if (expect(current, end, RIGHT_PAREN)) {m
        //     break;
        // }

        TokenItr tmp = *current;
        ServerConfig server_config;
        Result<int, std::string> result;
        if (expect(current, end, SERVER_BLOCK)) {
            result = parse_server_block(current, end, &server_config);
            http_config->servers.push_back(server_config);
        } else if (consume(current, end, KEEPALIVE_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&keepalive_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, KEEPALIVE_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &http_config->keepalive_timeout_sec,
                                             KEEPALIVE_TIMEOUT_DIRECTIVE,
                                             is_valid_keepalive_timeout);

        } else if (consume(current, end, RECV_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&recv_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, RECV_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &http_config->recv_timeout_sec,
                                             RECV_TIMEOUT_DIRECTIVE,
                                             is_valid_recv_timeout);

        } else if (consume(current, end, SEND_TIMEOUT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&send_timeout_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, SEND_TIMEOUT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_timeout_directive(current,
                                             end,
                                             &http_config->send_timeout_sec,
                                             SEND_TIMEOUT_DIRECTIVE,
                                             is_valid_send_timeout);
        } else {
            result = Result<int, std::string>::err(create_syntax_err_msg(*current, end));
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

    if (!consume(current, end, RIGHT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, RIGHT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    return Result<int, std::string>::ok(OK);
}
