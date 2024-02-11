#include <deque>
#include <iomanip>
#include <list>
#include <vector>
#include <mach/thread_info.h>

#include "Constant.hpp"
#include "Color.hpp"
#include "FileHandler.hpp"
#include "Token.hpp"
#include "Tokenizer.hpp"
#include "Parser.hpp"
#include "Server.hpp"
#include "TestParser.hpp"
#include "gtest/gtest.h"


void expect_eq_return(const ReturnDirective &expected,
                      const ReturnDirective &actual,
                      const std::size_t line) {
    EXPECT_EQ(expected.return_on, actual.return_on) << "  at L:" << line << std::endl;
    EXPECT_EQ(expected.code, actual.code) << "  at L:" << line << std::endl;
    EXPECT_EQ(expected.text, actual.text) << "  at L:" << line << std::endl;
}


void expect_eq_listen(const ListenDirective &expected,
                      const ListenDirective &actual,
                      const std::size_t line) {

    EXPECT_EQ(expected.address, actual.address) << "  at L:" << line << std::endl;
    EXPECT_EQ(expected.port, actual.port) << "  at L:" << line << std::endl;
}

void expect_eq_listens(const std::vector<ListenDirective> &expected,
                       const std::vector<ListenDirective> &actual,
                       const std::size_t line) {
    ASSERT_EQ(expected.size(), actual.size()) << "  at L:" << line << std::endl;

    std::vector<ListenDirective>::const_iterator expected_listen = expected.begin();
    std::vector<ListenDirective>::const_iterator actual_listen = actual.begin();
    while (expected_listen != expected.end()) {
        expect_eq_listen(*expected_listen, *actual_listen, line);
        ++expected_listen;
        ++actual_listen;
    }
}

void expect_eq_access_rules(const std::vector<AccessRule> &expected,
                            const std::vector<AccessRule> &actual,
                            const std::size_t line) {
    ASSERT_EQ(expected.size(), actual.size()) << "  at L:" << line << std::endl;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(expected[i].control, actual[i].control) << "  at L:" << line << std::endl;
        EXPECT_EQ(expected[i].specifier, actual[i].specifier) << "  at L:" << line << std::endl;
    }
}

void expect_eq_limit_except(const LimitExceptDirective &expected,
                            const LimitExceptDirective &actual,
                            const std::size_t line) {

    EXPECT_EQ(expected.excluded_methods, actual.excluded_methods) << "  at L:" << line;
    expect_eq_access_rules(expected.rules, actual.rules, line);
}


void expect_eq_default_config(const DefaultConfig &expected,
                              const DefaultConfig &actual,
                              const std::size_t line) {
    // root_path
    EXPECT_EQ(expected.root_path, actual.root_path) << "  at L:" << line;

    // index_pages
    EXPECT_EQ(expected.index_pages, actual.index_pages) << "  at L:" << line;

    // error_pages
    EXPECT_EQ(expected.error_pages, actual.error_pages) << "  at L:" << line;

    // autoindex
    EXPECT_EQ(expected.autoindex, actual.autoindex) << "  at L:" << line;

    // max_body_size
    EXPECT_EQ(expected.max_body_size_bytes, actual.max_body_size_bytes) << "  at L:" << line;
}


void expect_eq_location_config(const LocationConfig &expected,
                               const LocationConfig &actual,
                               const std::size_t line) {
    // return
    expect_eq_return(expected.redirection, actual.redirection, line);

    // limit_except
    expect_eq_limit_except(expected.limit_except, actual.limit_except, line);

    // default_config
    DefaultConfig expected_default_config = static_cast<const DefaultConfig &>(expected);
    DefaultConfig actual_default_config = static_cast<const DefaultConfig &>(actual);
    expect_eq_default_config(expected_default_config, actual_default_config, line);
}


void expect_eq_server_config(const ServerConfig &expected,
                             const ServerConfig &actual,
                             const std::size_t line) {

    expect_eq_listens(expected.listens, actual.listens, line);

    // default_server
    if (expected.default_server && actual.default_server) {
        expect_eq_listen(*expected.default_server, *actual.default_server, line);
    } else if (!(!expected.default_server && !actual.default_server)) {
        FAIL() << "  at L:" << line << std::endl;
    }

    // server_names
    EXPECT_EQ(expected.server_names, actual.server_names) << "  at L:" << line << std::endl;

    // default_server
    if (expected.default_server && actual.default_server) {
        expect_eq_listen(*expected.default_server, *actual.default_server, line);
        // std::cout << CYAN << "default_server ok" << RESET << std::endl;
    } else if (!(!expected.default_server && !actual.default_server)) {
        FAIL() << "  at L:" << line << std::endl;
    } else {
        // std::cout << CYAN << "default_server is null" << RESET << std::endl;
    }

    // locations
    ASSERT_EQ(expected.locations.size(), actual.locations.size()) << "  at L:" << line << std::endl;
    std::map<std::string, LocationConfig>::const_iterator expected_itr = expected.locations.begin();
    std::map<std::string, LocationConfig>::const_iterator actual_itr = actual.locations.begin();
    while (expected_itr != expected.locations.end()) {
        std::string expected_path = expected_itr->first;
        std::string actual_path = actual_itr->first;
        EXPECT_EQ(expected_path, actual_path) << "  at L:" << line << std::endl;

        LocationConfig expected_location = expected_itr->second;
        LocationConfig actual_location = actual_itr->second;
        expect_eq_location_config(expected_location, actual_location, line);

        ++expected_itr;
        ++actual_itr;
    }

    // default_config
    DefaultConfig expected_default_config = static_cast<const DefaultConfig &>(expected);
    DefaultConfig actual_default_config = static_cast<const DefaultConfig &>(actual);
    expect_eq_default_config(expected_default_config, actual_default_config, line);
}


void expect_eq_http_config(const HttpConfig &expected,
                           const HttpConfig &actual,
                           const std::size_t line) {

    ASSERT_EQ(expected.servers.size(), actual.servers.size()) << "  at L:" << line << std::endl;
    for (std::size_t i = 0; i < expected.servers.size(); ++i) {
        ServerConfig expected_server = expected.servers[i];
        ServerConfig actual_server = actual.servers[i];

        expect_eq_server_config(expected_server, actual_server, line);
    }
}


void expect_eq_locations(const std::map<std::string, LocationConfig> &expected,
                         const std::map<std::string, LocationConfig> &actual,
                         const std::size_t line) {

    ASSERT_EQ(expected.size(), actual.size()) << "  at L:" << line << std::endl;
    std::map<std::string, LocationConfig>::const_iterator expected_itr = expected.begin();
    std::map<std::string, LocationConfig>::const_iterator actual_itr = actual.begin();
    while (expected_itr != expected.end()) {
        EXPECT_EQ(expected_itr->first, actual_itr->first) << "  at L:" << line << std::endl;
        expect_eq_location_config(expected_itr->second, actual_itr->second, line);

        ++expected_itr;
        ++actual_itr;
    }
}


template <typename OkType>
void print_error_msg(Result<OkType, std::string> result, const std::size_t line) {
#ifdef DEBUG
    if (!result.is_err()) {
		std::cout << GRAY << "result is not error at L:" << line << RESET << std::endl;
        return;
	}
	std::string error_msg = result.get_err_value();
	std::cout << YELLOW << "error_msg: " << error_msg << RESET << " (test: L" << line << ")" << std::endl;
#else
    (void)result;
    (void)line;
#endif
}


void debug_print(const std::string &msg, const std::size_t line) {
#ifdef DEBUG
    std::cout << GRAY << "msg: " << msg << " (test: L" << line << ")" << RESET << std::endl;
#else
    (void)msg;
    (void)line;
#endif
}

////////////////////////////////////////////////////////////////////////////////


TEST(TestParser, ParseDirectiveParam) {
    const std::string test_directive = "test_param";
    std::string expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    expected = "test";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = "a";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = "            1       a     ";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    ///////////////////////////////////////////////////////////////////////////

    cnt = 0;
    expected = "test";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));  // ";" nothing

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = "test";
    tokens = {};  // token in empty
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);


    // -------------------------------------------------------------------------

    cnt = 0;
    expected = "test";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));  // ";" nothing
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = "test";
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));  // NONE-SINGLE parameters
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // first param is ";"

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));  // first param is "{"

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_param(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


TEST(TestParser, ParseDirectiveParams) {
    const std::string test_directive = "test_params";
    std::vector<std::string> expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    expected = {"1", "2", "3"};
    tokens = {};
    for (std::vector<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {"1"};
    tokens = {};
    for (std::vector<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    expected = {"1", "2", "3"};
    tokens = {};
    for (std::vector<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    // ";" nothing

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // first elem ";"

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};  // empty
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_directive_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


TEST(TestParser, ParseSetParams) {
    const std::string test_directive = "test_set_params";
    std::set<std::string> expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    expected = {"1", "2", "3"};
    tokens = {};
    for (std::set<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {"1"};
    tokens = {};
    for (std::set<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {"index.html", "index.htm", "index.html", "a", "a"};
    tokens = {};
    for (std::set<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    expected = {"1", "2", "3"};
    tokens = {};
    for (std::set<std::string>::const_iterator itr = expected.begin(); itr != expected.end(); ++itr) {
        tokens.push_back(Token(*itr, kTokenKindDirectiveParam, ++cnt));
    }
    // ";" nothing

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // first elem ";"

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};  // empty
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_set_params(current, tokens.end(), actual, test_directive);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


TEST(TestParser, ParseListenParam) {
    Result<AddressPortPair, int> result;
    AddressPortPair pair;
    std::string param, expected_addr, expected_port;

    param = "8080";
    expected_addr = "";
    expected_port = "8080";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_ok());
    pair = result.get_ok_value();
    EXPECT_EQ(expected_addr, pair.first);
    EXPECT_EQ(expected_port, pair.second);

    // -------------------------------------------------------------------------

    param = "127.0.0.1";
    expected_addr = "127.0.0.1";
    expected_port = "";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_ok());
    pair = result.get_ok_value();
    EXPECT_EQ(expected_addr, pair.first);
    EXPECT_EQ(expected_port, pair.second);

    // -------------------------------------------------------------------------

    param = "127.0.0.1:8080";
    expected_addr = "127.0.0.1";
    expected_port = "8080";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_ok());
    pair = result.get_ok_value();
    EXPECT_EQ(expected_addr, pair.first);
    EXPECT_EQ(expected_port, pair.second);


    ////////////////////////////////////////////////////////////////////////////

    param = "127.0.0.256:8080";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = "127.0.0.1a:8080";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = "127.0.0.1:8080a";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = ":8080";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = "";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = " :";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = " :8080       a";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());

    // -------------------------------------------------------------------------
    param = "127.0.0.0.:80";
    result = ParserTestFriend::parse_listen_param(param);
    ASSERT_TRUE(result.is_err());
}


TEST(TestParser, ParseListenDirective) {
    const std::string test_directive = "test_listen";
    std::vector<ListenDirective> expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "8080", false));

    tokens = {};
    tokens.push_back(Token("8080", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective("127.0.0.1", ConfigInitValue::kDefaultPort, false));

    tokens = {};
    tokens.push_back(Token("127.0.0.1", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective("127.0.0.1", "8080", false));

    tokens = {};
    tokens.push_back(Token("127.0.0.1:8080", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective("127.0.0.1", "8181", true));

    tokens = {};
    tokens.push_back(Token("127.0.0.1:8181", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("default_server", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective("127.0.0.1", "8181", false));
    expected.push_back(ListenDirective("127.0.0.1", "8080", true));
    expected.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "81", true));
    expected.push_back(ListenDirective("127.0.0.1", ConfigInitValue::kDefaultPort, false));

    tokens = {};
    tokens.push_back(Token("127.0.0.1:8181", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    tokens = {};
    tokens.push_back(Token("127.0.0.1:8080", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("default_server", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("#", kTokenKindComment, 3));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    tokens = {};
    tokens.push_back(Token("81", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("default_server", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    tokens = {};
    tokens.push_back(Token("#", kTokenKindComment, 3));
    tokens.push_back(Token("127.0.0.1", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);


    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    // duplicated case: unit ok -> validate ng
    cnt = 0;
    expected = {};
    expected.push_back(ListenDirective("127.0.0.1", "80", false));
    expected.push_back(ListenDirective("127.0.0.1", "80", true));

    tokens = {};
    tokens.push_back(Token("127.0.0.1:80", kTokenKindDirectiveParam, ++cnt));  // default port
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    tokens = {};
    tokens.push_back(Token("127.0.0.1", kTokenKindDirectiveParam, ++cnt));  // duplicated
    tokens.push_back(Token("default_server", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_listens(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};
    tokens.push_back(Token("127.0.0.1::8080", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};  // ng
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("127.0.0.1a:8080", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("default_server", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("127.0.0.1:8080a", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("127.0.0.1:8080", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("#", kTokenKindComment, ++cnt));
    tokens.push_back(Token("127.0.0.1:8080", kTokenKindDirectiveParam, 2));
    tokens.push_back(Token("#", kTokenKindComment, 3));
    tokens.push_back(Token("127.0.0.1:8080", kTokenKindDirectiveParam, 4));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, 5));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_listen_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}


TEST(TestParser, ParseReturnDirective) {
    const std::string test_directive = "test_return";
    ReturnDirective expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    expected = {};
    expected.code = 301;
    expected.text = "old_page";
    expected.return_on = true;

    tokens = {};
    tokens.push_back(Token("301", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("old_page", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_return(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.code = 301;
    expected.return_on = true;

    tokens = {};
    tokens.push_back(Token("301", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_return(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.code = 0;
    expected.text = "old_page";
    expected.return_on = true;

    tokens = {};
    tokens.push_back(Token("0", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("old_page", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_return(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    expected = {};
    expected.code = 999;
    expected.text = "old_page";
    expected.return_on = true;

    tokens = {};
    tokens.push_back(Token("999", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("old_page", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_return(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1000", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("+301", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("-800", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("301", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("oldpage", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("newpage", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};  // empty

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("301", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("oldpage", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_return_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}


TEST(TestParser, ParseRootDirective) {
    const std::string test_directive = "test_root";
    std::string expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    expected = "html";

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(expected, kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    // duplicated: unit ok -> error in parse_default_config()
    expected = "www";

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("www", kTokenKindDirectiveParam, ++cnt));  // ng: duplicated
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("a", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("a", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};  // ng
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_root_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


TEST(TestParser, ParseLimitExceptDirective) {
    const std::string test_directive = "test_limit_exception";
    LimitExceptDirective expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    expected = {};
    expected.excluded_methods = {kGET};

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_limit_except(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    expected = {};
    expected.excluded_methods = {kPOST};

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("POST", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_limit_except(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    expected = {};
    expected.excluded_methods = {kPOST};

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("PoSt", kTokenKindDirectiveParam, ++cnt));  // ok
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_limit_except(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    expected = {};
    expected.excluded_methods = {kDELETE};
    expected.rules.push_back(AccessRule(kDENY, "all"));

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("DELETE", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("deny", kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("all", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_limit_except(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    expected = {};
    expected.excluded_methods = {kGET, kPOST, kDELETE};

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("POST", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("DELETE", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_limit_except(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};  // ng
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));  // ng
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("hoge", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // ng
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("{", kTokenKindSemicolin, ++cnt));  // ng
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("location", kTokenKindBlockName, ++cnt));  // ng
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("allow", kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("xxx", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("GET", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));
    tokens.push_back(Token("deny", kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("all", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("hoge", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));
    tokens.push_back(Token("}", kTokenKindBraces, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_limit_except_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);


}


TEST(TestParser, ParseErrorPageDirective) {
    const std::string test_directive = "test_error_page";
    std::map<StatusCode, std::string> expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    expected = {
        {404, "/404.html"}
    };

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = {
        {404, "404"}
    };

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));  // ok
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = {
        {404, "/"}
    };

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/", kTokenKindDirectiveParam, ++cnt));  // ok
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = {
        {300, "/50x.html"},
        {404, "/404.html"},
        {500, "/50x.html"},
        {502, "/50x.html"},
        {503, "/50x.html"},
        {504, "overwrite"},
    };

    // error_page_directive 1
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);


    // error_page_directive 2
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("300", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("500", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("502", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("503", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("504", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/50x.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);


    // error_page_directive 3
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("504", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("overwrite", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = {
        {404, "/404.html"},
    };

    // error_page_directive 1
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);


    // error_page_directive 1
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("hoge", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    // error_page_directive 3
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};  // ng
    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("404a", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("600", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("199", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("499", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("300", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));  // ng

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_error_page_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}


TEST(TestParser, ParseAutoindexDirective) {
    const std::string test_directive = "test_autoindex";
    bool actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("on", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_TRUE(actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("On", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_TRUE(actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("off", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_FALSE(actual);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("ofF", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_FALSE(actual);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};  // error

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("on", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("off", kTokenKindDirectiveParam, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("true", kTokenKindDirectiveParam, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("false", kTokenKindDirectiveParam, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1", kTokenKindDirectiveParam, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);


    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("autoindex", kTokenKindDirectiveParam, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("on", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));  // error
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("{", kTokenKindBraces, ++cnt));  // error
    tokens.push_back(Token("on", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    actual = {};
    current = tokens.begin();
    result = ParserTestFriend::parse_autoindex_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}


TEST(TestParser, ParseBodySizeDirective) {
    const std::string test_directive = "test_autoindex";
    std::size_t expected, actual;
    Result<int, std::string> result;
    TokenConstItr current;
    std::deque<Token> tokens;
    int cnt;

    expected = 1 * ConfigInitValue::MB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1m", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 1 * ConfigInitValue::MB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1M", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 10 * ConfigInitValue::MB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("10m", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 1 * ConfigInitValue::KB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1k", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 1 * ConfigInitValue::MB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1M", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 2147483647;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("2147483647", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 9223372036854775807;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("9223372036854775807", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 9223372036854774784;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("9007199254740991k", kTokenKindDirectiveParam, ++cnt));  // < long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 9223372036853727232;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("8796093022207m", kTokenKindDirectiveParam, ++cnt));  // < long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = 9223372035781033984;
    cnt = 0;
    tokens = {};
    tokens.push_back(Token("8589934591g", kTokenKindDirectiveParam, ++cnt));  // < long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    // duplicated: unit ok -> error in parse_default_config()
    expected = 2 * ConfigInitValue::MB;

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1m", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);
    ASSERT_TRUE(result.is_ok());

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("2m", kTokenKindDirectiveParam, ++cnt));  // duplicated
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(expected, actual);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};  // ng
    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));  // ng

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1.0", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1.0m", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("1", kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("2", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("3", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("9223372036854775808", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("+1m", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("a", kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("9007199254740992k", kTokenKindDirectiveParam, ++cnt));  // > long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("8796093022208m", kTokenKindDirectiveParam, ++cnt));  // > long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("8589934592g", kTokenKindDirectiveParam, ++cnt));  // > long_max
    tokens.push_back(Token(";", kTokenKindSemicolin, ++cnt));

    current = tokens.begin();
    result = ParserTestFriend::parse_body_size_directive(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}


////////////////////////////////////////////////////////////////////////////////


TEST(TestParser, ParseDefaultConfig) {
    std::deque<Token> tokens;
    DefaultConfig expected, actual;
    TokenConstItr current;
    Result<int, std::string> result;
    int cnt;

    cnt = 0;
    tokens = {};
    current = tokens.begin();

    expected = {};
    actual = {};
    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_default_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("on",            kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("404",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/404.html",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("500",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("502",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("503",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("504",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/50x.html",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));


    tokens.push_back(Token("client_max_body_size",kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("2m",            kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    expected = {};
    expected.root_path = "html";
    expected.index_pages = {"index.html", "index.htm"};
    expected.autoindex = true;
    expected.max_body_size_bytes = 2 * ConfigInitValue::MB;
    expected.error_pages = {
        {404, "/404.html"},
        {500, "/50x.html"},
        {502, "/50x.html"},
        {503, "/50x.html"},
        {504, "/50x.html"},
    };

    actual = {};
    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_default_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("www",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("off",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("client_max_body_size", kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("0",             kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    expected = {};
    expected.root_path = "www";
    expected.index_pages = {"index.html", "index.htm"};
    expected.autoindex = false;
    expected.max_body_size_bytes = 0;

    actual = {};
    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_default_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("off",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("www",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("client_max_body_size", kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("1g",            kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    expected = {};
    expected.root_path = "www";
    expected.index_pages = {"index.htm"};
    expected.autoindex = false;
    expected.max_body_size_bytes = 1 * ConfigInitValue::GB;

    actual = {};
    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_default_config(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("www",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("off",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("on",            kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));  // ng
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));


    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("off",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("client_max_body_size",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("10",                    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",                     kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("client_max_body_size",  kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("1m",                    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",                     kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("client_max_body_size",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("10",                    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("10",                    kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";",                     kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("client_max_body_size",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("1mb",                   kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token(";",                     kTokenKindSemicolin, ++cnt));

    current = tokens.begin();

    result = ParserTestFriend::parse_default_config(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


TEST(TestParser, ParseLocationPath) {
    std::deque<Token> tokens;
    TokenConstItr current;
    Result<std::string, std::string> result;
    std::string expected, actual;
    int cnt;

    cnt = 0;

    expected = "path";

    tokens = {};
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = "/";

    tokens = {};
    tokens.push_back(Token("/",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = "=path";

    tokens = {};
    tokens.push_back(Token("=",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);

    // -------------------------------------------------------------------------

    expected = "^~path";

    tokens = {};
    tokens.push_back(Token("^~",    kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_ok());
    actual = result.get_ok_value();
    EXPECT_EQ(expected, actual);


    ////////////////////////////////////////////////////////////////////////////

    tokens = {};
    tokens.push_back(Token("=",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("^~",    kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("=",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("=path", kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("=path", kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("=",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("^~",    kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("=path", kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------
    tokens = {};
    tokens.push_back(Token("=",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("^~path",kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("=path", kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("===path",   kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("path",  kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",     kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    tokens = {};
    tokens.push_back(Token("=",         kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("^~path",    kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));
    current = tokens.begin();

    result = ParserTestFriend::parse_location_path(current, tokens.end());

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}

// "location"  path  "{"  directive_name ... "}"
// ^current
TEST(TestParser, ParseLocation) {
    std::deque<Token> tokens;
    std::map<std::string, LocationConfig> expected, actual;
    LocationConfig location_config;
    TokenConstItr current;
    Result<int, std::string> result;
    int cnt;


    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",   kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/",          kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",          kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",          kTokenKindBraces, ++cnt));

    current = tokens.begin();

    location_config = {};
    expected = {};
    expected["/"] = location_config;

    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_locations(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("path",          kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("on",            kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("client_max_body_size",kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("2m",            kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));


    current = tokens.begin();

    location_config = {};
    location_config.root_path = "html";
    location_config.index_pages = {"index.html", "index.htm"};
    location_config.limit_except.excluded_methods = {kGET};
    location_config.autoindex = true;
    location_config.max_body_size_bytes = 2 * ConfigInitValue::MB;

    expected = {};
    expected["path"] = location_config;

    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    print_error_msg(result, __LINE__);

    ASSERT_TRUE(result.is_ok());
    expect_eq_locations(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/old_page",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("return",        kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("301",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/new_page",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("DELETE",        kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("deny",          kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("all",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("return",        kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("333",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("/ignored",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));


    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    current = tokens.begin();

    location_config = {};
    location_config.redirection.return_on = true;
    location_config.redirection.code = 301;
    location_config.redirection.text = "/new_page";
    location_config.limit_except.excluded_methods = {kGET, kDELETE};
    location_config.limit_except.rules.push_back(AccessRule(kDENY, "all"));

    expected = {};
    expected["/old_page"] = location_config;

    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_locations(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////

    cnt = 0;
    tokens = {};

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("ng",        kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------


    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("listen",    kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("8080",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("ng",        kTokenKindDirectiveParam, ++cnt));  // ng
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));  // ng
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    expected = {};
    expected["/path"] = location_config;

    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindDirectiveParam, ++cnt));

    current = tokens.begin();

    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("location",  kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("xxx",       kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",         kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("DELETE",        kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("DELETE",        kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",         kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("DELETE",        kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    current = tokens.begin();


    actual = {};
    result = ParserTestFriend::parse_location(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

}


// "server"  "{"  directive_name ... "}"
//                ^current
TEST(TestParser, ParseServer) {
    std::deque<Token> tokens;
    ServerConfig expected, actual;
    LocationConfig location_config;
    ListenDirective listen;
    TokenConstItr current;
    Result<int, std::string> result;
    int cnt;

    cnt = 0;
    tokens = {};

    tokens.push_back(Token("server",        kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("listen",        kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("8080",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("listen",        kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("8181",          kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token("default_server",kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));


    tokens.push_back(Token("server_name",   kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("localhost",     kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));  // out of responsibility

    current = tokens.begin();

    expected = {};
    expected.listens.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "8080", false));
    expected.listens.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "8181", true));
    expected.server_names.insert("localhost");

    actual = {};
    result = ParserTestFriend::parse_server_block(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_server_config(expected, actual, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};
    tokens.push_back(Token("server",        kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));

    tokens.push_back(Token("listen",        kTokenKindDirectiveName, ++cnt));           // server
    tokens.push_back(Token("8080",          kTokenKindDirectiveParam, ++cnt));          // server
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));               // server

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));           // server
    tokens.push_back(Token("400",           kTokenKindDirectiveParam, ++cnt));          // server
    tokens.push_back(Token("server_error_page",kTokenKindDirectiveParam, ++cnt));   // server
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));               // server

    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));           // location
    tokens.push_back(Token("/path",         kTokenKindBlockParam, ++cnt));      // location
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));              // location

    tokens.push_back(Token("root",          kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("html",          kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("index",         kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("index.html",    kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("index.htm",     kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("limit_except",  kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("GET",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));              // location
    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));              // location

    tokens.push_back(Token("autoindex",     kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("on",            kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("client_max_body_size",kTokenKindDirectiveName, ++cnt)); // location
    tokens.push_back(Token("2m",            kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("404",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("/404.html",     kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));       // location
    tokens.push_back(Token("500",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("502",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("503",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("504",           kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token("/50x.html",     kTokenKindDirectiveParam, ++cnt));      // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));           // location

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));              // location


    tokens.push_back(Token("server_name",   kTokenKindDirectiveName, ++cnt));   // server
    tokens.push_back(Token("localhost",     kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token("localhost",     kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token("webserv",       kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));       // server


    tokens.push_back(Token("location",      kTokenKindBlockName, ++cnt));       // location
    tokens.push_back(Token("/old_page",     kTokenKindBlockParam, ++cnt));  // location
    tokens.push_back(Token("{",             kTokenKindBraces, ++cnt));          // location

    tokens.push_back(Token("return",        kTokenKindDirectiveName, ++cnt));   // location
    tokens.push_back(Token("301",           kTokenKindDirectiveParam, ++cnt));  // location
    tokens.push_back(Token("/new_page",     kTokenKindDirectiveParam, ++cnt));  // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));       // location

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));   // location
    tokens.push_back(Token("400",           kTokenKindDirectiveParam, ++cnt));  // location
    tokens.push_back(Token("test_error",    kTokenKindDirectiveParam, ++cnt));  // location
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));       // location

    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));          // location


    tokens.push_back(Token("server_name",   kTokenKindDirectiveName, ++cnt));   // server
    tokens.push_back(Token("a",             kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token("b",             kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));       // server

    tokens.push_back(Token("error_page",    kTokenKindDirectiveName, ++cnt));   // server
    tokens.push_back(Token("599",           kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token("error",         kTokenKindDirectiveParam, ++cnt));  // server
    tokens.push_back(Token(";",             kTokenKindSemicolin, ++cnt));       // server


    tokens.push_back(Token("}",             kTokenKindBraces, ++cnt));

    current = tokens.begin();

    expected = {};
    expected.listens.push_back(ListenDirective(ConfigInitValue::kDefaultAddress, "8080", false));
    expected.server_names.insert("localhost");
    expected.server_names.insert("webserv");
    expected.server_names.insert("a");
    expected.server_names.insert("b");
    expected.error_pages = {
        {400, "server_error_page"},
        {599, "error"},
    };


    location_config = {};
    location_config.root_path = "html";
    location_config.index_pages = {"index.html", "index.htm"};
    location_config.limit_except.excluded_methods = {kGET};
    location_config.autoindex = true;
    location_config.max_body_size_bytes = 2 * ConfigInitValue::MB;
    location_config.error_pages = {
        {404, "/404.html"},
        {500, "/50x.html"},
        {502, "/50x.html"},
        {503, "/50x.html"},
        {504, "/50x.html"},
    };
    expected.locations["/path"] = location_config;

    location_config = {};
    location_config.redirection.return_on = true;
    location_config.redirection.code = 301;
    location_config.redirection.text = "/new_page";
    location_config.error_pages = {
        {400, "test_error"},
    };

    expected.locations["/old_page"] = location_config;

    actual = {};
    result = ParserTestFriend::parse_server_block(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_ok());
    expect_eq_server_config(expected, actual, __LINE__);


    ////////////////////////////////////////////////////////////////////////////


    cnt = 0;
    tokens = {};

    tokens.push_back(Token("server",    kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("listen",    kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("8080",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("root",      kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));


    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));  // ng
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("root",      kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));


    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();

    actual = {};
    result = ParserTestFriend::parse_server_block(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);

    // -------------------------------------------------------------------------

    cnt = 0;
    tokens = {};

    tokens.push_back(Token("server",    kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("listen",    kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("8080",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("location",  kTokenKindBlockName, ++cnt));
    tokens.push_back(Token("/path",     kTokenKindBlockParam, ++cnt));
    tokens.push_back(Token("{",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("root",      kTokenKindDirectiveName, ++cnt));
    tokens.push_back(Token("html",      kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    tokens.push_back(Token("deny",      kTokenKindDirectiveName, ++cnt));  // ng
    tokens.push_back(Token("all",       kTokenKindDirectiveParam, ++cnt));
    tokens.push_back(Token(";",         kTokenKindSemicolin, ++cnt));

    tokens.push_back(Token("}",         kTokenKindBraces, ++cnt));

    current = tokens.begin();

    actual = {};
    result = ParserTestFriend::parse_server_block(current, tokens.end(), actual);

    ASSERT_TRUE(result.is_err());
    print_error_msg(result, __LINE__);
}
