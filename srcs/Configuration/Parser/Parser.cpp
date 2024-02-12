#include <deque>
#include <limits>
#include <set>
#include <utility>
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Parser.hpp"
#include "Tokenizer.hpp"
#include "StringHandler.hpp"
#include "HttpMessageParser.hpp"


Parser::Parser() {}


Parser::Parser(const char *file_path) {
    FileHandler file_handler(file_path, CONFIG_FILE_EXTENSION);
    Result<int, std::string> read_file_result = file_handler.get_result();
    if (read_file_result.is_err()) {
        const std::string error_msg = read_file_result.get_err_value();
        this->result_ = Result<int, std::string>::err(error_msg);
        return;
    }
    std::string conf_data = file_handler.get_contents();


    Tokenizer tokenizer(conf_data);
    Result<int, std::string> tokenize_result = tokenizer.get_result();
    if (tokenize_result.is_err()) {
        const std::string error_msg = tokenize_result.get_err_value();
        this->result_ = Result<int, std::string>::err(error_msg);
        return;
    }
    std::deque<Token> tokens = tokenizer.get_tokens();


    Result<HttpConfig, std::string> parse_result = parse(tokens);
	if (parse_result.is_err()) {
		std::string error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	HttpConfig http_config = parse_result.get_ok_value();

    set_default_server_name(&http_config);
    set_default_listen(&http_config);

    Result<int, std::string> validate_result = validate(http_config);
	if (validate_result.is_err()) {
		std::string error_msg = validate_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

    this->http_config_ = http_config;
	this->result_ = Result<int, std::string>::ok(OK);
    set_default_server();
}


Parser::Parser(const Parser &other) {
	*this = other;
}


Parser::~Parser() {}


Parser &Parser::operator=(const Parser &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->http_config_ = rhs.http_config_;
	this->result_ = rhs.result_;
	return *this;
}


Result<HttpConfig, std::string> Parser::parse(const std::deque<Token> &tokens) {
    HttpConfig http_config;
    TokenItr current = tokens.begin();
    const TokenItr end = tokens.end();


    Result<int, std::string> skip_result = skip_events_block(&current, end);
    if (skip_result.is_err()) {
        const std::string error_msg = skip_result.get_err_value();
        return Result<HttpConfig, std::string>::err(error_msg);
    }

    Result<int, std::string> result = parse_http_block(&current, end, &http_config);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<HttpConfig, std::string>::err(error_msg);
    }

    if (!is_at_end(&current, end)) {
        const std::string error_msg = create_syntax_err_msg(current, end);
        return Result<HttpConfig, std::string>::err(error_msg);
    }

	return Result<HttpConfig, std::string>::ok(http_config);
}


// server_block内に同一のip, portはNG
Result<int, std::string> validate_listen(const std::vector<ServerConfig> &server_configs) {
    std::vector<ServerConfig>::const_iterator server_config;
    for (server_config = server_configs.begin(); server_config != server_configs.end(); ++server_config) {
        const std::vector<ListenDirective> listens = server_config->listens;

        std::set<AddressPortPair> address_port_pairs;

        std::vector<ListenDirective>::const_iterator listen;
        for (listen = listens.begin(); listen != listens.end(); ++listen) {
            AddressPortPair pair = std::make_pair(listen->address, listen->port);
            if (address_port_pairs.find(pair) != address_port_pairs.end()) {
                std::ostringstream oss;
                oss << "duplicate listen \"" << listen->address << ":" << listen->port << "\"";
                return Result<int, std::string>::err(oss.str());
            }
            address_port_pairs.insert(pair);
        }
    }
    return Result<int, std::string>::ok(OK);
}


// validate conflict to other server
Result<int, std::string> validate_server(const std::vector<ServerConfig> &server_configs) {
    std::set<ServerInfo> server_informations;

    std::vector<ServerConfig>::const_iterator server_config;
    for (server_config = server_configs.begin(); server_config != server_configs.end(); ++server_config) {
        const std::vector<ListenDirective> listens = server_config->listens;
        const std::set<std::string> &server_names = server_config->server_names;

        std::set<std::string>::const_iterator server_name;
        for (server_name = server_names.begin(); server_name != server_names.end(); ++server_name) {
            std::vector<ListenDirective>::const_iterator listen;
            for (listen = listens.begin(); listen != listens.end(); ++listen) {
                ServerInfo info = ServerInfo(*server_name, listen->address, listen->port);
                // std::cout << CYAN << " name:" << info.server_name
                // << ", address:" << info.address
                // << ", port:" << info.port << RESET << std::endl;

                if (server_informations.find(info) != server_informations.end()) {
                    std::ostringstream oss;
                    oss << "conflicting server name \"" << info.server_name << "\"";
                    oss << " on \"" << info.address << ":" << info.port << "\"";
                    return Result<int, std::string>::err(oss.str());
                }
                server_informations.insert(info);
            }
        }
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Parser::validate(const HttpConfig &http_config) {
    Result<int, std::string> listen_result = validate_listen(http_config.servers);
    if (listen_result.is_err()) {
        const std::string error_msg = listen_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    Result<int, std::string> server_result = validate_server(http_config.servers);
    if (server_result.is_err()) {
        const std::string error_msg = server_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }
	return Result<int, std::string>::ok(OK);
}


void Parser::set_default_listen(HttpConfig *http_config) {
    std::vector<ServerConfig>::iterator server_config = http_config->servers.begin();
    while (server_config != http_config->servers.end()) {
        if (server_config->listens.empty()) {
            server_config->listens.push_back(ListenDirective());
        }
        ++server_config;
    }
}


void Parser::set_default_server_name(HttpConfig *http_config) {
    std::vector<ServerConfig>::iterator server_config = http_config->servers.begin();
    while (server_config != http_config->servers.end()) {
        if (server_config->server_names.empty()) {
            server_config->server_names.insert(ConfigInitValue::kDefaultServerName);
        }
        ++server_config;
    }
}



void Parser::set_default_server() {
    std::vector<ServerConfig>::iterator server_config = this->http_config_.servers.begin();

    while (server_config != this->http_config_.servers.end()) {
        std::vector<ListenDirective> &listens = server_config->listens;
        std::vector<ListenDirective>::iterator listen = listens.begin();

        server_config->default_server = &(*listen);
        while (listen != listens.end()) {
            if (listen->is_default_server) {
                server_config->default_server = &(*listen);
                break;
            }
            ++listen;
        }
        ++server_config;
    }
}


Result<int, std::string> Parser::get_result() const { return result_; }


HttpConfig Parser::get_config() const { return http_config_; }


bool Parser::is_at_end(TokenItr *current, const TokenItr end) {
    skip_comments(current, end);

    return *current == end;
}


bool Parser::consume(TokenItr *current, const TokenItr end, const std::string &expected_str) {
    skip_comments(current, end);

    if (*current != end && (*current)->str_ == expected_str) {
        ++(*current);
        return true;
    }
    return false;
}


bool Parser::consume(TokenItr *current, const TokenItr end, TokenKind expected_kind) {
    skip_comments(current, end);

    if (*current != end && (*current)->kind_ == expected_kind) {
        ++(*current);
        return true;
    }
    return false;
}


bool Parser::expect(TokenItr *current, const TokenItr end, const std::string &expected_str) {
    skip_comments(current, end);

    if (*current == end) {
        return false;
    }
    return (*current)->str_ == expected_str;
}


bool Parser::expect(TokenItr *current, const TokenItr end, TokenKind expected_kind) {
    skip_comments(current, end);

    if (*current == end) {
        return false;
    }
    return (*current)->kind_ == expected_kind;
}


void Parser::skip_comments(TokenItr *current, const TokenItr end) {
    while (*current != end && (*current)->kind_ == kTokenKindComment) {
        ++(*current);
    }
}


// "event"  "{"  "}"
// ^current           ^return
Result<int, std::string> Parser::skip_events_block(TokenItr *current,
                                                   const TokenItr end) {
    if (!current) {
        return Result<int, std::string>::err("fatal error");
    }

    while (*current != end) {
        if (!consume(current, end, EVENTS_BLOCK)) {
            break;
        }
        if (!consume(current, end, LEFT_PAREN)) {
            const std::string error_msg = create_syntax_err_msg(*current, end, LEFT_PAREN);
            return Result<int, std::string>::err(error_msg);
        }
        if (!consume(current, end, RIGHT_PAREN)) {
            const std::string error_msg = create_syntax_err_msg(*current, end, RIGHT_PAREN);
            return Result<int, std::string>::err(error_msg);
        }
    }
    return Result<int, std::string>::ok(OK);
}


// "http"  "{"  "server"  "{" ... "}" ... "}"
// ^current                                    ^return
Result<int, std::string> Parser::parse_http_block(TokenItr *current,
                                                  const TokenItr end,
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

    while (*current != end) {
        if (!expect(current, end, SERVER_BLOCK)) {
            break;
        }
        if (expect(current, end, RIGHT_PAREN)) {
            break;
        }

        TokenItr tmp = *current;
        ServerConfig server_config;
        Result<int, std::string> result = parse_server_block(current, end, &server_config);
        if (result.is_err()) {
            const std::string error_msg = result.get_err_value();
            return Result<int, std::string>::err(error_msg);
        }
        if (tmp == *current) {
            const std::string error_msg = create_syntax_err_msg(*current, end);
            return Result<int, std::string>::err(error_msg);
        }

        http_config->servers.push_back(server_config);
    }

    if (!consume(current, end, RIGHT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, RIGHT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    return Result<int, std::string>::ok(OK);
}


// "server"  "{"  directive_name ... "}"
// ^current                               ^return
Result<int, std::string> Parser::parse_server_block(TokenItr *current,
                                                    const TokenItr end,
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
        } else if (expect(current, end, LOCATIONS_BLOCK)) {
            result = skip_location(current, end, &location_iterators);
        } else {
            result = parse_default_config(current, end, server_config);
        }
        if (result.is_err()) {
            const std::string error_msg = result.get_err_value();
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
        const std::string error_msg = location_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}




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

Result<std::string, std::string> Parser::parse_location_path(TokenItr *current,
                                                             const TokenItr end) {
    if (!current) {
        return Result<std::string, std::string>::err("fatal error");
    }

    if (*current == end) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LOCATIONS_BLOCK);
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
            const std::string error_msg = create_invalid_value_err_msg(prefix, LOCATIONS_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
    } else {
        if (!is_matching_operator(prefix)) {
            const std::string error_msg = create_invalid_value_err_msg(prefix, LOCATIONS_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
        if (is_start_with_matching_operator(suffix)) {
            const std::string error_msg = create_invalid_value_err_msg(suffix, LOCATIONS_BLOCK);
            return Result<std::string, std::string>::err(error_msg);
        }
    }
    std::string path = prefix + suffix;

    if (!expect(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LOCATIONS_BLOCK);
        return Result<std::string, std::string>::err(error_msg);
    }
    return Result<std::string, std::string>::ok(path);
}


// "location" [ = | ^~ ]  path  "{"  directive_name ...  ... "}"
//  ^current                         ^                        ^return
//                                   location_start
Result<int, std::string> Parser::skip_location(TokenItr *current,
                                               const TokenItr end,
                                               LocationItrMap *location_iterators) {
    if (!current || !location_iterators) {
        return Result<int, std::string>::err("fatal error");
    }

    if (!consume(current, end, LOCATIONS_BLOCK)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, "location_path");
        return Result<int, std::string>::err(error_msg);
    }

    Result<std::string, std::string> path_result = parse_location_path(current, end);
    if (path_result.is_err()) {
        const std::string error_msg = path_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }
    std::string location_path = path_result.get_ok_value();

    if (!consume(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, LEFT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    TokenItr location_start = *current;
    LocationConfig unused;
    Result<int, std::string> result = parse_location_block(current, end, &unused);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (expect(current, end, LOCATIONS_BLOCK)) {
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
Result<int, std::string> Parser::parse_location(const LocationItrMap &location_iterators,
                                                const LocationConfig &init_config,
                                                const TokenItr end,
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
            const std::string error_msg = result.get_err_value();
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


bool is_duplicated(int *cnt) {
    ++(*cnt);
    return *cnt != 1;
}

void clear_initial_value(std::set<std::string> *params, int *cnt) {
    ++(*cnt);

    if (*cnt == 1) {
        params->clear();
    }
}


// "location"  path  "{"  directive_name ...  "}"
//                        ^current             ^return
Result<int, std::string> Parser::parse_location_block(TokenItr *current,
                                                      const TokenItr end,
                                                      LocationConfig *location_config) {
    Result<int, std::string> result;
    int limit_except_cnt = 0;

    if (!current || !location_config) {
        return Result<int, std::string>::err("fatal error");
    }

    while (*current != end) {
        if (expect(current, end, LOCATIONS_BLOCK)) {
            break;
        }
        if (expect(current, end, RIGHT_PAREN)) {
            break;
        }

        TokenItr tmp = *current;
        if (consume(current, end, RETURN_DIRECTIVE)) {
            result = parse_return_directive(current, end, &location_config->redirection);

        } else if (consume(current, end, LIMIT_EXCEPT_DIRECTIVE)) {
            if (is_duplicated(&limit_except_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, LIMIT_EXCEPT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_limit_except_directive(current, end, &location_config->limit_except);

        } else {
            result = parse_default_config(current, end, location_config);
        }

        if (result.is_err()) {
            const std::string error_msg = result.get_err_value();
            return Result<int, std::string>::err(error_msg);
        }
        if (tmp == *current) {
            const std::string error_msg = create_syntax_err_msg(*current, end);
            return Result<int, std::string>::err(error_msg);
        }
    }
    return Result<int, std::string>::ok(OK);
}


// directive_name  directive_param ... ;
// ^current                               ^return
Result<int, std::string> Parser::parse_default_config(TokenItr *current,
                                                      const TokenItr end,
                                                      DefaultConfig *default_config) {
    int root_cnt = 0;
    int index_cnt = 0;
    int autoindex_cnt = 0;
    int max_body_size_cnt = 0;

    if (!current || !default_config) {
        return Result<int, std::string>::err("fatal error");
    }

    while (*current != end) {
        Result<int, std::string> result;
        if (consume(current, end, ROOT_DIRECTIVE)){
            if (is_duplicated(&root_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, ROOT_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_root_directive(current, end, &default_config->root_path);

        } else if (consume(current, end, INDEX_DIRECTIVE)) {
            clear_initial_value(&default_config->index_pages, &index_cnt);
            result = parse_set_params(current, end, &default_config->index_pages, INDEX_DIRECTIVE);

        } else if (consume(current, end, ERROR_PAGE_DIRECTIVE)) {
            result = parse_error_page_directive(current, end, &default_config->error_pages);

        } else if (consume(current, end, AUTOINDEX_DIRECTIVE)) {
            if (is_duplicated(&autoindex_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, AUTOINDEX_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_autoindex_directive(current, end, &default_config->autoindex);

        } else if (consume(current, end, BODY_SIZE_DIRECTIVE)) {
            if (is_duplicated(&max_body_size_cnt)) {
                const std::string error_msg = create_duplicated_directive_err_msg(*current, end, BODY_SIZE_DIRECTIVE);
                return Result<int, std::string>::err(error_msg);
            }
            result = parse_body_size_directive(current, end, &default_config->max_body_size_bytes);

        } else { break; }

        if (result.is_err()) {
            const std::string error_msg = result.get_err_value();
            return Result<int, std::string>::err(error_msg);
        }
    }
    return Result<int, std::string>::ok(OK);
}


Result<AddressPortPair, int> Parser::parse_listen_param(const std::string &param) {
    if (param.empty()) {
        return Result<std::pair<std::string, std::string>, int>::err(ERR);
    }

    std::string address, port;
    std::size_t pos, end;

    pos = 0;
    HttpMessageParser::skip_ipv4address(param, pos, &end);
    std::size_t len = end - pos;
    address = param.substr(pos, len);

    pos = end;
    if (pos < param.length()) {
        if (0 < pos && param[pos] == COLON) { ++pos; }  // param = ":8080" is invalid

        HttpMessageParser::skip_port(param, pos, &end);
        if (pos == end || end != param.length()) {
            return Result<std::pair<std::string, std::string>, int>::err(ERR);
        }
        port = param.substr(pos);
    }

    const AddressPortPair pair = std::make_pair(address, port);
    return Result<std::pair<std::string, std::string>, int>::ok(pair);
}


// "listen" ( address[:port] / port ) [default_server]  ";"
//          ^current                                         ^return
Result<int, std::string> Parser::parse_listen_directive(TokenItr *current,
                                                        const TokenItr end,
                                                        std::vector<ListenDirective> *listen_directives) {
    std::vector<std::string> listen_params;
    ListenDirective listen_directive;
    Result<int, std::string> result;

    if (!current || !listen_directives) {
        return Result<int, std::string>::err("fatal error");
    }

    result = parse_directive_params(current, end, &listen_params, LISTEN_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
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
    AddressPortPair pair = param_result.get_ok_value();
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


// directive_name  directive_param ... ";"
//                 ^current                ^return
Result<int, std::string> Parser::parse_directive_params(TokenItr *current,
                                                        const TokenItr end,
                                                        std::vector<std::string> *params,
                                                        const std::string &directive_name) {
    std::vector<std::string> parsed_params;

    if (!current || !params) {
        return Result<int, std::string>::err("fatal error");
    }

    while (expect(current, end, kTokenKindDirectiveParam)) {
        parsed_params.push_back((*current)->str_);
        ++(*current);
    }
    if (parsed_params.empty()) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, directive_name);
        return Result<int, std::string>::err(error_msg);
    }
    if (!consume(current, end, kTokenKindSemicolin)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, std::string(1, SEMICOLON));
        return Result<int, std::string>::err(error_msg);
    }

    params->insert((*params).end(), parsed_params.begin(), parsed_params.end());
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Parser::parse_set_params(TokenItr *current,
                                                  const TokenItr end,
                                                  std::set<std::string> *params,
                                                  const std::string &name) {
    std::vector<std::string> parsed_params;

    Result<int, std::string> parse_result;

    parse_result = parse_directive_params(current, end, &parsed_params, name);
    if (parse_result.is_err()) {
        const std::string error_msg = parse_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    std::vector<std::string>::const_iterator itr;
    for (itr = parsed_params.begin(); itr != parsed_params.end(); ++itr) {
        params->insert(*itr);
    }
    return Result<int, std::string>::ok(OK);
}


// directive_name  directive_param ";"
//                 ^current             ^return
Result<int, std::string> Parser::parse_directive_param(TokenItr *current,
                                                       const TokenItr end,
                                                       std::string *param,
                                                       const std::string &directive_name) {
    if (!current || !param) {
        return Result<int, std::string>::err("fatal error");
    }

    if (!expect(current, end, kTokenKindDirectiveParam)) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, directive_name);
        return Result<int, std::string>::err(error_msg);
    }

    *param = (*current)->str_;
    ++(*current);

    if (!consume(current, end, kTokenKindSemicolin)) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, directive_name);
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}


bool Parser::is_valid_return_code(StatusCode code) {
    return 0 <= code && code <= 999;
}


// "return" code [text]  ";"
//          ^current
Result<int, std::string> Parser::parse_return_directive(TokenItr *current,
                                                        const TokenItr end,
                                                        ReturnDirective *redirection) {
    std::vector<std::string> return_params;
    Result<int, std::string> result;

    if (!current || !redirection) {
        return Result<int, std::string>::err("fatal error");
    }

    result = parse_directive_params(current, end, &return_params, RETURN_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (return_params.empty() || 2 < return_params.size()) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, RETURN_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }

    std::vector<std::string>::const_iterator param = return_params.begin();
    bool succeed;
    StatusCode code = HttpMessageParser::to_integer_num(*param, &succeed);
    if (!succeed || !is_valid_return_code(code)) {
        const std::string error_msg = create_invalid_value_err_msg(*param, RETURN_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }

    if (redirection->return_on) {
        return Result<int, std::string>::ok(OK);
    }

    redirection->code = code;
    ++param;
    if (param != return_params.end()) {
        redirection->text = *param;
    }
    redirection->return_on = true;
    return Result<int, std::string>::ok(OK);
}


// "root"  path  ";"
//         ^current   ^return
Result<int, std::string> Parser::parse_root_directive(TokenItr *current,
                                                      const TokenItr end,
                                                      std::string *root_path) {
    if (!current || !root_path) {
        return Result<int, std::string>::err("fatal error");
    }

    Result<int, std::string> result;
    result = parse_directive_param(current, end, root_path, ROOT_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }
    return Result<int, std::string>::ok(OK);
}


Result<Method, std::string> Parser::get_method(const std::string & method) {
    const std::string lower = StringHandler::to_lower(method);  // todo: toupper?

    if (lower == "get") { return Result<Method, std::string>::ok(kGET); }
    if (lower == "post") { return Result<Method, std::string>::ok(kPOST); }
    if (lower == "delete") { return Result<Method, std::string>::ok(kDELETE); }

    std::ostringstream oss;
    oss << "invalid method \"" << method << "\"";
    return Result<Method, std::string>::err(oss.str());
}


bool Parser::is_access_rule_directive(TokenItr *current, const TokenItr end) {
    return expect(current, end, ALLOW_DIRECTIVE)
           || expect(current, end, DENY_DIRECTIVE);
}

Result<int, std::string> Parser::parse_access_rule(TokenItr *current,
                                                   const TokenItr end,
                                                   std::vector<AccessRule> *rules,
                                                   const std::string &name) {
    if (!current || !rules) {
        return Result<int, std::string>::err("fatal error");
    }

    while (*current != end) {
        if (expect(current, end, RIGHT_PAREN)) {
            break;
        }

        if (!is_access_rule_directive(current, end)) {
            break;
        }

        AccessControl control = ((*current)->str_ == "allow") ? kALLOW : kDENY;
        ++(*current);

        std::string specifier;
        Result<int, std::string> parse_result;
        parse_result = parse_directive_param(current, end, &specifier, name);
        if (parse_result.is_err()) {
            const std::string error_msg = parse_result.get_err_value();

            return Result<int, std::string>::err(error_msg);
        }
        if (specifier != "all" && !HttpMessageParser::is_ipv4address(specifier)) {
            const std::string error_msg = create_invalid_value_err_msg(specifier, name);
            return Result<int, std::string>::err(error_msg);
        }
        rules->push_back(AccessRule(control, specifier));
    }
    return Result<int, std::string>::ok(OK);
}


//  "limit_except"  method ... "{" ...  ";"  "}"
//                  ^current                      ^return
Result<int, std::string> Parser::parse_limit_except_directive(TokenItr *current,
                                                              const TokenItr end,
                                                              LimitExceptDirective *limit_except) {
    if (!current || !limit_except) {
        return Result<int, std::string>::err("fatal error");
    }

    while (expect(current, end, kTokenKindDirectiveParam)) {
        Result<Method, std::string> result = get_method((*current)->str_);

        if (result.is_err()) {
            const std::string error_msg = result.get_err_value();
            return Result<int, std::string>::err(error_msg);
        }

        Method excluded_method = result.get_ok_value();
        limit_except->excluded_methods.insert(excluded_method);

        ++(*current);
    }
    if (limit_except->excluded_methods.empty()) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, LIMIT_EXCEPT_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }

    if (!consume(current, end, LEFT_PAREN)) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, LEFT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    Result<int, std::string> skip_result;
    skip_result = parse_access_rule(current, end, &limit_except->rules, LIMIT_EXCEPT_DIRECTIVE);
    if (skip_result.is_err()) {
        const std::string error_msg = skip_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (!consume(current, end, RIGHT_PAREN)) {
        const std::string error_msg = create_syntax_err_msg(*current, end, RIGHT_PAREN);
        return Result<int, std::string>::err(error_msg);
    }

    return Result<int, std::string>::ok(OK);
}


bool Parser::is_valid_error_code(StatusCode code) {
    return (300 <= code && code <=599 && code != 499);
}


// "error_page"  code ... uri  ";"
//               ^current           ^return
Result<int, std::string> Parser::parse_error_page_directive(TokenItr *current,
                                                            const TokenItr end,
                                                            std::map<StatusCode, std::string> *error_pages) {
    std::vector<std::string> error_page_params;
    Result<int, std::string> result;

    if (!current || !error_pages) {
        return Result<int, std::string>::err("fatal error");
    }

    result = parse_directive_params(current, end, &error_page_params, ERROR_PAGE_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    if (error_page_params.size() < 2) {
        const std::string error_msg = create_invalid_num_of_arg_err_msg(*current, end, ERROR_PAGE_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }

    const std::string error_page = error_page_params.back();
    error_page_params.pop_back();

    std::vector<std::string>::const_iterator param;
    for (param = error_page_params.begin(); param != error_page_params.end(); ++param) {
        bool succeed;
        StatusCode code = HttpMessageParser::to_integer_num(*param, &succeed);
        if (!succeed || !is_valid_error_code(code)) {
            const std::string error_msg = create_invalid_value_err_msg(*param, ERROR_PAGE_DIRECTIVE);
            return Result<int, std::string>::err(error_msg);
        }
        (*error_pages)[code] = error_page;  // overwrite
    }
    return Result<int, std::string>::ok(OK);
}


// "autoindex"  on | off  ";"
//              ^current      ^return
Result<int, std::string> Parser::parse_autoindex_directive(TokenItr *current,
                                                           const TokenItr end,
                                                           bool *autoindex) {
    std::string autoindex_param;

    if (!current || !autoindex) {
        return Result<int, std::string>::err("fatal error");
    }

    Result<int, std::string> result;
    result = parse_directive_param(current, end, &autoindex_param, AUTOINDEX_DIRECTIVE);
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    autoindex_param = StringHandler::to_lower(autoindex_param);
    if (autoindex_param != "on" && autoindex_param != "off") {
        std::ostringstream oss;
        oss << "invalid value \""  << autoindex_param << "\"";
        oss << " in \""  << AUTOINDEX_DIRECTIVE  << "\" directive, it must be \"on\" or \"off\"";;
        return Result<int, std::string>::err(oss.str());
    }
    *autoindex = (autoindex_param == "on") ? true : false;
    return Result<int, std::string>::ok(OK);
}


Result<std::size_t, int> Parser::parse_size_with_prefix(const std::string &size_str) {
    if (size_str.empty()) {
        return Result<std::size_t, int>::err(ERR);
    }

    if (!std::isdigit(size_str[0])) {
        return Result<std::size_t, int>::err(ERR);
    }

    bool is_overflow;
    std::size_t pos;
    long body_size = StringHandler::stol(size_str, &pos, &is_overflow);
    if (is_overflow) {
        return Result<std::size_t, int>::err(ERR);
    }
    std::size_t size = static_cast<std::size_t>(body_size);
    // std::cout << CYAN << "bytes: " << size << RESET << std::endl;
    // std::cout << CYAN << "end  :[" << &size_str[pos] << "]" << RESET << std::endl;

    if (pos  < size_str.length()) {
        const char prefix = std::tolower(size_str[pos]);
        // std::cout << CYAN << "prefix: " << prefix << RESET << std::endl;
        ++pos;

        std::size_t multiplier;
        switch (prefix) {
            case 'k':
                multiplier = ConfigInitValue::KB;
                break;

            case 'm':
                multiplier = ConfigInitValue::MB;
                break;

            case 'g':
                multiplier = ConfigInitValue::GB;
                break;

            default:
                return Result<std::size_t, int>::err(ERR);
        }

        if (std::numeric_limits<long>::max() / multiplier < size) {
            return Result<std::size_t, int>::err(ERR);
        }
        size *= multiplier;
    }
    if (pos != size_str.length()) {
        return Result<std::size_t, int>::err(ERR);
    }
    return Result<std::size_t, int>::ok(size);
}


// "client_max_body_size"  size | size_with_prefix(k,m,g)  ";"
//                         ^current                             ^return
Result<int, std::string> Parser::parse_body_size_directive(TokenItr *current,
                                                           const TokenItr end,
                                                           std::size_t *max_body_size_bytes) {
    std::string body_size_param;

    if (!current || !max_body_size_bytes) {
        return Result<int, std::string>::err("fatal error");
    }

    Result<int, std::string> param_result;
    param_result = parse_directive_param(current, end, &body_size_param, BODY_SIZE_DIRECTIVE);
    if (param_result.is_err()) {
        const std::string error_msg = param_result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    Result<std::size_t, int> size_result = parse_size_with_prefix(body_size_param);
    if (size_result.is_err()) {
        const std::string error_msg = create_invalid_value_err_msg(body_size_param, BODY_SIZE_DIRECTIVE);
        return Result<int, std::string>::err(error_msg);
    }
    *max_body_size_bytes = size_result.get_ok_value();
    return Result<int, std::string>::ok(OK);
}


////////////////////////////////////////////////////////////////////////////////


std::string Parser::create_syntax_err_msg(const TokenItr current,
                                          const TokenItr end) {
    std::ostringstream oss;

    if (current == end) {
        oss << "syntax error: unexpected end of file";
    } else {
        oss << "syntax error: unexpected \"" << current->str_ << "\"";
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string Parser::create_syntax_err_msg(const TokenItr current,
                                          const TokenItr end,
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


std::string Parser::create_invalid_value_err_msg(const TokenItr current,
                                                 const TokenItr end) {
    std::ostringstream oss;

    oss << "invalid value";
    if (current != end)  {
        oss << " \""  << current->str_  << "\"";
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string Parser::create_invalid_value_err_msg(const TokenItr current,
                                                 const TokenItr end,
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


std::string Parser::create_invalid_value_err_msg(const std::string &invalid_value,
                                                 const std::string &directive_name) {
    std::ostringstream oss;

    oss << "invalid value \""  << invalid_value << "\" in \"" << directive_name << "\" directive";
    return oss.str();
}


std::string Parser::create_invalid_num_of_arg_err_msg(const TokenItr current,
                                                      const TokenItr end,
                                                      const std::string &directive_name) {
    std::ostringstream oss;

    oss << "invalid number of arguments in \"" <<  directive_name << "\" directive";
    if (current != end) {
        oss << ": in L" << current->line_number_;
    }
    return oss.str();
}


std::string Parser::create_duplicated_directive_err_msg(const TokenItr current,
                                                        const TokenItr end,
                                                        const std::string &directive_name) {
    std::ostringstream oss;

    oss << "\""  << directive_name  << "\" directive is duplicate";
    if (current != end)  {
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string Parser::create_duplicated_location_err_msg(const TokenItr current,
                                                       const TokenItr end,
                                                       const std::string &path) {
    std::ostringstream oss;

    oss << "duplicate location \""  << path  << "\"";
    if (current != end)  {
        oss << " in L" << current->line_number_;
    }
    return oss.str();
}


std::string Parser::create_recursive_location_err_msg(const TokenItr current,
                                                      const TokenItr end,
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
