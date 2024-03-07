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


namespace {

// ok: path
// ng: =path, ^~path
bool is_start_with_matching_operator(const std::string &str) {
    if (str.empty()) {
        return false;
    }
    return (str[0] == '='
            || (2 <= str.length() && str[0] == '^' && str[1] == '~'));
}

bool is_matching_operator(const std::string &str) {
    return str == "=" || str == "^~";
}


}  // namespace


// "location"  path  "{"  directive_name ...  "}"
//                        ^current             ^return
Result<int, std::string> ConfigParser::parse_location_block(TokenItr *current,
                                                            const TokenItr &end,
                                                            LocationConfig *location_config) {
    Result<int, std::string> result;
    int limit_except_cnt = 0;

    if (!current || !location_config) {
        return Result<int, std::string>::err("fatal error");
    }

    while (*current != end) {
        if (expect(current, end, LOCATION_BLOCK)) {
            break;
        }
        if (expect(current, end, RIGHT_PAREN)) {
            break;
        }

        TokenItr tmp = *current;
        if (consume(current, end, RETURN_DIRECTIVE)) {
            result = parse_return_directive(current, end, &location_config->redirection);

        } else if (consume(current, end, LIMIT_EXCEPT_DIRECTIVE)) {
            if (ConfigParser::is_duplicated(&limit_except_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, LIMIT_EXCEPT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_limit_except_directive(current, end, &location_config->limit_except);

        } else if (consume(current, end, CGI_MODE_DIRECTIVE)) {
            result = parse_cgi_mode_directive(current, end, &location_config->cgi.is_cgi_mode);
        } else if (consume(current, end, CGI_EXTENSION_DIRECTIVE)) {
            result = parse_set_params(current, end, &location_config->cgi.extension, CGI_EXTENSION_DIRECTIVE);

        } else if (consume(current, end, CGI_TIMEOUT_DIRECTIVE)) {
            result = parse_timeout_directive(current, end, &location_config->cgi.timeout_sec, CGI_TIMEOUT_DIRECTIVE, is_valid_cgi_timeout);

        } else {
            result = parse_default_config(current, end, location_config);
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
    return Result<int, std::string>::ok(OK);
}


Result<std::string, std::string> ConfigParser::parse_location_path(TokenItr *current,
                                                                   const TokenItr &end) {
    if (!current) {
        return Result<std::string, std::string>::err("fatal error");
    }

    if (*current == end) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LOCATION_BLOCK);
        return Result<std::string, std::string>::err(error_msg);
    }

    std::string prefix = (*current)->str_;
    ++(*current);

    std::string suffix;
    if (expect(current, end, kTokenKindBlockParam)) {
        suffix = (*current)->str_;
        ++(*current);
    }

    // std::cout << CYAN << "prefix:" << prefix << ", suffix:" << suffix << RESET << std::endl;
    if (suffix.empty()) {
        if (is_start_with_matching_operator(prefix)) {
            const std::string error_msg = create_invalid_value_err_msg(prefix, LOCATION_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
    } else {
        if (!is_matching_operator(prefix)) {
            const std::string error_msg = create_invalid_value_err_msg(prefix, LOCATION_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
        if (is_start_with_matching_operator(suffix)) {
            const std::string error_msg = create_invalid_value_err_msg(suffix, LOCATION_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
    }
    std::string path = prefix + suffix;

    if (!expect(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LOCATION_BLOCK);
        return Result<std::string, std::string>::err(error_msg);
    }
    return Result<std::string, std::string>::ok(path);
}


// "location" [ = | ^~ ]  path  "{"  directive_name ...  ... "}"
//  ^current                         ^                        ^return
//                                   location_start
Result<int, std::string> ConfigParser::skip_location(TokenItr *current,
                                                     const TokenItr &end,
                                                     LocationItrMap *location_iterators) {
    if (!current || !location_iterators) {
        return Result<int, std::string>::err("fatal error");
    }

    if (!consume(current, end, LOCATION_BLOCK)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, "location_path");
        return Result<int, std::string>::err(error_msg);
    }

    Result<std::string, std::string> path_result = parse_location_path(current, end);
    if (path_result.is_err()) {
        const std::string error_msg = path_result.err_value();
        return Result<int, std::string>::err(error_msg);
    }
    std::string location_path = path_result.ok_value();

    if (!consume(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LEFT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    TokenItr location_start = *current;
    LocationConfig unused;
    Result<int, std::string> result = parse_location_block(current, end, &unused);
    if (result.is_err()) {
        const std::string error_msg = result.err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (expect(current, end, LOCATION_BLOCK)) {
        const std::string error_msg = create_recursive_location_err_msg(*current, end, location_path);
        return Result<int, std::string>::err(error_msg);
    }
    if (location_iterators->find(location_path) != location_iterators->end()) {
        const std::string error_msg = create_duplicated_location_err_msg(*current, end, location_path);
        return Result<int, std::string>::err(error_msg);
    }
    (*location_iterators)[location_path] = location_start;

    if (!consume(current, end, RIGHT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, RIGHT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}


// "location" [ = | ^~ ]  path  "{"  directive_name ...   "}"
//                                   ^start                      ^end
Result<int, std::string> ConfigParser::parse_location(const LocationItrMap &location_iterators,
                                                      const LocationConfig &init_config,
                                                      const TokenItr &end,
                                                      std::map<std::string, LocationConfig> *locations) {
    if (!locations) {
        return Result<int, std::string>::err("fatal error");
    }
    for (LocationItrMap::const_iterator i = location_iterators.begin(); i != location_iterators.end(); ++i) {
        const std::string location_path = i->first;
        TokenItr start = i->second;

        LocationConfig location_config(init_config);
        Result<int, std::string> result = parse_location_block(&start, end, &location_config);
        if (result.is_err()) {
            const std::string error_msg = result.err_value();
            return Result<int, std::string>::err(error_msg);
        }

        if (locations->find(location_path) != locations->end()) {
            const std::string error_msg = create_duplicated_location_err_msg(start, end, location_path);
            return Result<int, std::string>::err(error_msg);
        }
        (*locations)[location_path] = location_config;

        if (!consume(&start, end, RIGHT_PAREN)) {
            const std::string error_msg = create_duplicated_location_err_msg(start, end, location_path);
            return Result<int, std::string>::err(error_msg);
        }
    }
    return Result<int, std::string>::ok(OK);
}
