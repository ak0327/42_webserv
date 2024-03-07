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


std::string ConfigParser::create_syntax_err_msg(const TokenItr &current,
                                                const TokenItr &end) {
    std::ostringstream oss;

    if (current == end) {
        oss << "syntax error: unexpected end of file";
    } else {
        oss << "syntax error: unexpected \"" << current->str_ << "\"";
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_syntax_err_msg(const TokenItr &current,
                                                const TokenItr &end,
                                                const std::string &expecting) {
    std::ostringstream oss;

    if (current == end) {
        oss << "syntax error: unexpected end of file";
        oss << ": expecting \"" << expecting << "\"";
    } else {
        oss << "syntax error: unexpected \"" << current->str_ << "\"";
        oss << ": expecting \"" << expecting << "\"";
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_invalid_value_err_msg(const TokenItr &current,
                                                       const TokenItr &end) {
    std::ostringstream oss;

    oss << "invalid value";
    if (current != end)  {
        oss << " \""  << current->str_  << "\"";
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_invalid_value_err_msg(const TokenItr &current,
                                                       const TokenItr &end,
                                                       const std::string &directive_name) {
    std::ostringstream oss;

    oss << "invalid value";
    if (current != end)  {
        oss << " \""  << current->str_  << "\"";
        oss << " in \""  << directive_name  << "\" directive";
        oss << " in L" << current->line_number_;
    } else {
        oss << " in \""  << directive_name  << "\" directive";
    }
    return oss.str();
}


std::string ConfigParser::create_invalid_value_err_msg(const std::string &invalid_value,
                                                       const std::string &directive_name) {
    std::ostringstream oss;

    oss << "invalid value \""  << invalid_value << "\" in \"" << directive_name << "\" directive";
    return oss.str();
}


std::string ConfigParser::create_invalid_num_of_arg_err_msg(const TokenItr &current,
                                                            const TokenItr &end,
                                                            const std::string &directive_name) {
    std::ostringstream oss;

    oss << "invalid number of arguments in \"" <<  directive_name << "\" directive";
    if (current != end) {
        oss << ": in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_duplicated_directive_err_msg(const TokenItr &current,
                                                              const TokenItr &end,
                                                              const std::string &directive_name) {
    std::ostringstream oss;

    oss << "\""  << directive_name  << "\" directive is duplicate";
    if (current != end)  {
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_duplicated_location_err_msg(const TokenItr &current,
                                                             const TokenItr &end,
                                                             const std::string &path) {
    std::ostringstream oss;

    oss << "duplicate location \""  << path  << "\"";
    if (current != end)  {
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string ConfigParser::create_recursive_location_err_msg(const TokenItr &current,
                                                            const TokenItr &end,
                                                            const std::string &outside) {
    std::ostringstream oss;
    TokenItr next;

    if (current != end) {
        next = current;
        ++next;
        oss << "location \""  << (next->kind_ == kTokenKindDirectiveParam ? next->str_ : "") << "\"";
        oss << " in location \"" << outside << "\"";
    } else {
        oss << "location in location \"" << outside << "\"";
    }
    if (current != end)  {
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}
