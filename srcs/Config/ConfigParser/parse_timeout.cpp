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

Result<time_t, int> ConfigParser::parse_timeout_with_prefix(const std::string &timeout_str,
                                                            bool (*validate_func)(time_t)) {
    if (timeout_str.empty()) {
        return Result<time_t, int>::err(ERR);
    }

    if (!std::isdigit(timeout_str[0])) {
        return Result<time_t, int>::err(ERR);
    }

    bool is_overflow;
    std::size_t pos;
    int int_timeout = StringHandler::stoi(timeout_str, &pos, &is_overflow);
    if (is_overflow || int_timeout < 0) {
        return Result<time_t, int>::err(ERR);
    }
    time_t timeout_sec = static_cast<time_t>(int_timeout);
    // std::cout << CYAN << "bytes: " << timeout_sec << RESET << std::endl;
    // std::cout << CYAN << "end  :[" << &timeout_str[pos] << "]" << RESET << std::endl;

    if (pos  < timeout_str.length()) {
        const char prefix = std::tolower(timeout_str[pos]);
        // std::cout << CYAN << "prefix: " << prefix << RESET << std::endl;
        ++pos;

        time_t multiplier;
        switch (prefix) {
            case 's':
                multiplier = 1;
                break;

            case 'm':
                multiplier = 60;
                break;

            default:
                return Result<time_t, int>::err(ERR);
        }

        if (std::numeric_limits<long>::max() / multiplier < timeout_sec) {
            return Result<time_t, int>::err(ERR);
        }
        timeout_sec *= multiplier;
    }
    if (pos != timeout_str.length()) {
        return Result<time_t, int>::err(ERR);
    }
    if (!validate_func(timeout_sec)) {
        return Result<time_t, int>::err(ERR);
    }
    return Result<time_t, int>::ok(timeout_sec);
}


// "XXX_timeout"  timeout(s) | timeout_with_prefix(s,m)  ";"
//                ^current                       ^return
Result<int, std::string> ConfigParser::parse_timeout_directive(TokenItr *current,
                                                               const TokenItr &end,
                                                               time_t *timeout_sec,
                                                               const std::string &directive_name,
                                                               bool (*validate_func)(time_t)) {
    std::string timeout_str;

    if (!current || !timeout_sec) {
        return Result<int, std::string>::err("fatal error");
    }

    Result<int, std::string> param_result;
    param_result = parse_directive_param(current, end, &timeout_str, directive_name);
    if (param_result.is_err()) {
        const std::string error_msg = param_result.err_value();
        return Result<int, std::string>::err(error_msg);
    }

    Result<time_t, int> size_result = parse_timeout_with_prefix(timeout_str, validate_func);
    if (size_result.is_err()) {
        const std::string error_msg = create_invalid_value_err_msg(timeout_str, directive_name);
        return Result<int, std::string>::err(error_msg);
    }
    *timeout_sec = size_result.ok_value();
    return Result<int, std::string>::ok(OK);
}


bool ConfigParser::is_valid_cgi_timeout(time_t timeout_sec) {
    return ConfigInitValue::kMinCgiTimeoutSec <= timeout_sec
           && timeout_sec <= ConfigInitValue::kMaxCgiTImeoutSec;
}


bool ConfigParser::is_valid_session_timeout(time_t timeout_sec) {
    return ConfigInitValue::kMinSessionTimeoutSec <= timeout_sec
           && timeout_sec <= ConfigInitValue::kMaxSessionTimeoutSec;
}


bool ConfigParser::is_valid_keepalive_timeout(time_t timeout_sec) {
    return ConfigInitValue::kMinKeepaliveTimeoutSec <= timeout_sec
           && timeout_sec <= ConfigInitValue::kMaxKeepaliveTimeoutSec;
}


bool ConfigParser::is_valid_client_header_timeout(time_t timeout_sec) {
    return ConfigInitValue::kMinHeaderTimeoutSec <= timeout_sec
           && timeout_sec <= ConfigInitValue::kMaxHeaderTimeoutSec;
}


bool ConfigParser::is_valid_client_body_timeout(time_t timeout_sec) {
    return ConfigInitValue::kMinBodyTimeoutSec <= timeout_sec
           && timeout_sec <= ConfigInitValue::kMaxBodyTimeoutSec;
}
