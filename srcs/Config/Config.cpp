#include <fstream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include "webserv.hpp"
#include "Config.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Token.hpp"
#include "ConfigParser.hpp"

Config::Config(const char *file_path) {
	ConfigParser parser(file_path);
    Result<int, std::string> parse_result = parser.result();
	if (parse_result.is_err()) {
		const std::string error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

    this->http_config_ = parser.config();
    set_server_configs();
    Result<int, std::string> result = set_default_servers();
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        this->result_ = Result<int, std::string>::err(error_msg);
        return;
    }
	this->result_ = Result<int, std::string>::ok(OK);
}


Config::Config(const Config &other) {
	*this = other;
}


Config::~Config() {}


Config &Config::operator=(const Config &rhs) {
	if (this == &rhs) {
		return *this;
	}

	this->http_config_ = rhs.http_config_;
	this->result_ = rhs.result_;
	return *this;
}


void Config::set_server_configs() {
    const std::vector<ServerConfig> &server_configs = this->http_config_.servers;

    std::vector<ServerConfig>::const_iterator server_config;
    for (server_config = server_configs.begin(); server_config != server_configs.end(); ++server_config) {
        const std::vector<ListenDirective> &listens = server_config->listens;
        const std::set<std::string> &server_names = server_config->server_names;

        std::set<std::string>::const_iterator server_name;
        for (server_name = server_names.begin(); server_name != server_names.end(); ++server_name) {
            std::vector<ListenDirective>::const_iterator listen;
            for (listen = listens.begin(); listen != listens.end(); ++listen) {
                ServerInfo info = ServerInfo(*server_name, listen->address, listen->port);

                this->server_configs_[info] = &(*server_config);
            }
        }
    }
}


std::ostream &operator<<(std::ostream &out, const AddressPortPair &pair) {
    out << pair.first << ":" << pair.second;
    return out;
}


std::ostringstream &operator<<(std::ostringstream &out, const std::map<AddressPortPair, const ServerConfig *> &default_servers) {
    for (std::map<AddressPortPair, const ServerConfig *>::const_iterator itr = default_servers.begin(); itr != default_servers.end(); ++itr) {
        out << itr->first << std::endl;
    }
    return out;
}


Result<int, std::string> Config::set_default_server_to_default_listen() {
    const std::vector<ServerConfig> &server_configs = this->http_config_.servers;

    std::vector<ServerConfig>::const_iterator server_config;
    for (server_config = server_configs.begin(); server_config != server_configs.end(); ++server_config) {
        const std::vector<ListenDirective> &listens = server_config->listens;
        std::vector<ListenDirective>::const_iterator listen;
        for (listen = listens.begin(); listen != listens.end(); ++listen) {
            if (!listen->is_default_server) {
                continue;
            }

            AddressPortPair pair(listen->address, listen->port);
            if (this->default_servers_.find(pair) != this->default_servers_.end()) {
                std::ostringstream oss;
                oss << "duplicate default server for " << listen->address << ":" << listen->port;
                return Result<int, std::string>::err(oss.str());
            }
            // std::cout << CYAN << "default_listen: " << pair << RESET << std::endl;
            this->default_servers_[pair] = &(*server_config);
        }
    }
    return Result<int, std::string>::ok(OK);
}


void Config::set_default_server_to_first_listen() {
    const std::vector<ServerConfig> &server_configs = this->http_config_.servers;

    std::vector<ServerConfig>::const_iterator server_config;
    for (server_config = server_configs.begin(); server_config != server_configs.end(); ++server_config) {
        const std::vector<ListenDirective> &listens = server_config->listens;
        std::vector<ListenDirective>::const_iterator listen;
        for (listen = listens.begin(); listen != listens.end(); ++listen) {
            AddressPortPair pair(listen->address, listen->port);
            if (this->default_servers_.find(pair) != this->default_servers_.end()) {
                continue;
            }
            // std::cout << CYAN << "first_listen: " << pair << RESET << std::endl;
            this->default_servers_[pair] = &(*server_config);
        }
    }
}


Result<int, std::string> Config::set_default_servers() {
    Result<int, std::string> result = set_default_server_to_default_listen();
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    set_default_server_to_first_listen();

    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Config::get_result() const { return this->result_; }


std::map<ServerInfo, const ServerConfig *> Config::get_server_configs() const {
    return this->server_configs_;
}


Result<ServerConfig, int> Config::get_server_config(const ServerInfo &server_info) const {
    std::map<ServerInfo, const ServerConfig *>::const_iterator server_config;
    server_config = this->server_configs_.find(server_info);

    if (server_config != this->server_configs_.end()) {
        return Result<ServerConfig, int>::ok(*server_config->second);
    } else {
        AddressPortPair pair(server_info.address, server_info.port);
        return get_default_server(pair);
    }
}


// todo: address == "*"
Result<ServerConfig, std::string> Config::get_server_config(const AddressPortPair &actual,
                                                            const HostPortPair &request) const {
    std::string socket_address = actual.first;
    std::string socket_port = actual.second;
    std::string request_port = request.second;
    Result<ServerConfig, int> result;

    if (socket_address == "0.0.0.0") { socket_address = "*"; }  // todo
    // std::cout << CYAN << "actual  addr: " << socket_address << ", port: " << socket_port << RESET << std::endl;
    // std::cout << CYAN << "request addr: " << request.first << ", port: " << request.second << RESET << std::endl;
    // DEBUG_PRINT(CYAN, "get_server_config");

    if (!request_port.empty() && request_port != socket_port) {
        return Result<ServerConfig, std::string>::err("error: request ip not found");
    }
    // DEBUG_PRINT(CYAN, " 1");

    if (HttpMessageParser::is_ipv4address(request.first)) {
        // DEBUG_PRINT(CYAN, " 2");
        std::string request_address = request.first;
        // ipv4
        if (socket_address == request_address) {
            result = get_default_server(actual);
            if (result.is_err()) {
                // DEBUG_PRINT(CYAN, " 3 err");
                return Result<ServerConfig, std::string>::err("error");
            }
            // DEBUG_PRINT(CYAN, " 4 ok");
            return Result<ServerConfig, std::string>::ok(result.get_ok_value());
        } else if (socket_address == "*") {  // todo
            // DEBUG_PRINT(CYAN, " 5");
            AddressPortPair pair(request_address, socket_port);
            result = get_default_server(actual);
            if (result.is_err()) {
                // DEBUG_PRINT(CYAN, " 6 err");
                return Result<ServerConfig, std::string>::err("error");
            }
            // DEBUG_PRINT(CYAN, " 7 ok");
            return Result<ServerConfig, std::string>::ok(result.get_ok_value());
        } else {
            // DEBUG_PRINT(CYAN, " 8 err");
            return Result<ServerConfig, std::string>::err("error: address is not mach with conf and request");
        }
    } else if (HttpMessageParser::is_ipv6address(request.first)) {
        // ivp6
        // DEBUG_PRINT(CYAN, " 9 err");
        return Result<ServerConfig, std::string>::err("error");  // todo: ipv6
    } else {
        std::string request_server_name = request.first;
        // DEBUG_PRINT(CYAN, " server_name: %s", request_server_name.c_str());
        ServerInfo server_info(request_server_name, socket_address, socket_port);
        result = get_server_config(server_info);
        if (result.is_err()) {
            // DEBUG_PRINT(CYAN, " 10 err");
            return Result<ServerConfig, std::string>::err("error");
        }
        // DEBUG_PRINT(CYAN, " 11 ok");
        return Result<ServerConfig, std::string>::ok(result.get_ok_value());
    }
}


Result<ServerConfig, int> Config::get_default_server(const AddressPortPair &pair) const {
    std::map<AddressPortPair, const ServerConfig *> ::const_iterator default_server;
    default_server = this->default_servers_.find(pair);

    if (default_server != this->default_servers_.end()) {
        return Result<ServerConfig, int>::ok(*default_server->second);
    } else {
        return Result<ServerConfig, int>::err(ERR);
    }
}


bool Config::is_exact_match(const std::string &pattern, const std::string &target) {
    if (pattern.empty() || target.empty()) {
        return false;
    }
    if (pattern[0] != '=') {
        return false;
    }
    std::string comparison_path = pattern.substr(1);
    return comparison_path == target;
}


bool Config::is_prefix_match(const std::string &pattern, const std::string &target) {
    if (pattern.empty() || target.empty()) {
        return false;
    }

    const std::size_t PREFIX_LEN = 2;
    if (pattern.length() <= PREFIX_LEN || target.length() + PREFIX_LEN < pattern.length()) {
        return false;
    }
    if (pattern[0] != '^' || pattern[1] != '~') {
        return false;
    }
    std::string comparison_path = pattern.substr(PREFIX_LEN);
    std::string matching_substr = target.substr(0, comparison_path.length());
    return comparison_path == matching_substr;
}


std::string get_pattern_matching_path(const ServerConfig &server_config,
                                      const std::string &target_path) {
    std::string matching_location;

    std::map<LocationPath, LocationConfig>::const_iterator location;
    for (location = server_config.locations.begin(); location != server_config.locations.end(); ++location) {
        std::string config_location = location->first;
        if (Config::is_exact_match(config_location, target_path)) {
            matching_location = config_location;
            break;
        }
        if (Config::is_prefix_match(config_location, target_path)) {
            if (matching_location.length() < config_location.length()) {
                matching_location = config_location;
            }
        }
    }
    return matching_location;
}


std::string find_basic_matching_path(const ServerConfig &server_config,
                                    const std::string &target_path) {
    std::string matching_location;

    std::map<LocationPath, LocationConfig>::const_iterator location;
    for (location = server_config.locations.begin(); location != server_config.locations.end(); ++location) {
        std::string config_location = location->first;

        if (target_path.length() < config_location.length()) {
            continue;
        }
        std::string location_extension = StringHandler::get_extension(config_location);
        if (!location_extension.empty()) {
            if (target_path == config_location) {
                matching_location = config_location;
                break;
            }
            continue;
        }
        std::string target_prefix = target_path.substr(0, config_location.length());
        if (target_prefix == config_location) {
            if (matching_location.length() < config_location.length()) {
                matching_location = config_location;
            }
        }
    }
    return matching_location;
}


Result<std::string, int> Config::get_matching_location(const ServerConfig &server_config,
                                                       const std::string &target_path) {
    std::string matching_location;

    matching_location = get_pattern_matching_path(server_config, target_path);
    if (!matching_location.empty()) {
        // DEBUG_PRINT(WHITE, "target[%s] matches location[%s]", target_path.c_str(), matching_location.c_str());
        // std::cout << RED << "pattern_matching: target[" << target_path << "], location[" << matching_location << "]" << RESET << std::endl;
        return Result<std::string, int>::ok(matching_location);
    }

    matching_location = find_basic_matching_path(server_config, target_path);
    if (!matching_location.empty()) {
        // DEBUG_PRINT(WHITE, "target[%s] matches location[%s]", target_path.c_str(), matching_location.c_str());
        // std::cout << RED << "find_matching_path: target[" << target_path << "], location[" << matching_location << "]" << RESET << std::endl;
        return Result<std::string, int>::ok(matching_location);
    }
    // DEBUG_PRINT(WHITE, "target[%s] matches location[NOTHING]", target_path.c_str());
    return Result<std::string, int>::err(ERR);
}


Result<LocationConfig, int> Config::get_location_config(const ServerConfig &server_config,
                                                        const std::string &target_path) {
    Result<std::string, int> matching_result = Config::get_matching_location(server_config, target_path);
    if (matching_result.is_err()) {
        DEBUG_PRINT(WHITE, "target[%s] matches location[NOTHING]", target_path.c_str());
        return Result<LocationConfig, int>::err(ERR);
    }
    const std::string matching_location = matching_result.get_ok_value();
    DEBUG_PRINT(WHITE, "target[%s] matches location[%s]", target_path.c_str(), matching_location.c_str());
    std::map<LocationPath, LocationConfig>::const_iterator location;
    location = server_config.locations.find(matching_location);
    if (location == server_config.locations.end()) {
        return Result<LocationConfig, int>::err(ERR);
    }
    return Result<LocationConfig, int>::ok(location->second);
}


Result<std::string, int> Config::get_root(const ServerConfig &server_config,
                                          const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    } else {
        LocationConfig location = location_result.get_ok_value();
        return Result<std::string, int>::ok(location.root_path);
    }
}


Result<std::string, int> Config::get_root(const ServerInfo &server_info,
                                          const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_root(server_config, target_path);
}


Result<std::string, int> Config::get_root(const AddressPortPair &address_port_pair,
                                          const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_root(server_config, target_path);
}


Result<std::string, int> Config::get_index(const ServerConfig &server_config,
                                           const std::string &target_path) {
    std::set<std::string> index_pages;

    // DEBUG_PRINT(GREEN, "get_index target: %s", target_path.c_str());
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    LocationConfig location_config = location_result.get_ok_value();
    index_pages = location_config.index_pages;

    Result<std::string, int> root_result = get_root(server_config, target_path);
    if (root_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    const std::string root = root_result.get_ok_value();
    // DEBUG_PRINT(GREEN, " root: %s", root.c_str());

    for (std::set<std::string>::const_iterator page = index_pages.begin(); page != index_pages.end(); ++page) {
        const std::string path = root + target_path + *page;
        // DEBUG_PRINT(GREEN, " path: %s", path.c_str());
        std::ifstream ifs(path.c_str());

        if (ifs.is_open()) {
            ifs.close();
            // DEBUG_PRINT(GREEN, " -> index: ", path.c_str());
            return Result<std::string, int>::ok(*page);
        }
    }
    // DEBUG_PRINT(GREEN, " index_page nothing ");
    return Result<std::string, int>::err(ERR);
}


Result<std::string, int> Config::get_index(const ServerInfo &server_info,
                                           const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);

    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_index(server_config, target_path);
}


Result<std::string, int> Config::get_index(const AddressPortPair &address_port_pair,
                                           const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_index(server_config, target_path);
}


Result<std::string, int> Config::get_error_page_path(const ServerConfig &server_config,
                                                     const std::string &target_path,
                                                     const StatusCode &code) {
    Result<std::string, int> root_result = Config::get_root(server_config, target_path);
    if (root_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    std::string root = root_result.get_ok_value();

    Result<std::string, int> error_page_result = Config::get_error_page(server_config, target_path, code);
    if (error_page_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    std::string error_page = error_page_result.get_ok_value();
    return Result<std::string, int>::ok(root + error_page);
}


Result<std::string, int> Config::get_error_page(const ServerConfig &server_config,
                                                const std::string &target_path,
                                                const StatusCode &code) {
    std::map<StatusCode, std::string> error_pages;
    std::string root;

    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    DefaultConfig config;

    if (location_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }

    LocationConfig location_config = location_result.get_ok_value();
    error_pages = location_config.error_pages;

    if (error_pages.find(code) == error_pages.end()) {
        return Result<std::string, int>::err(ERR);
    }

    return Result<std::string, int>::ok(error_pages[code]);
}


Result<std::string, int> Config::get_error_page(const ServerInfo &server_info,
                                                const std::string &target_path,
                                                const StatusCode &code) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_error_page(server_config, target_path, code);
}


Result<std::string, int> Config::get_error_page(const AddressPortPair &address_port_pair,
                                                const std::string &target_path,
                                                const StatusCode &code) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_error_page(server_config, target_path, code);
}


Result<bool, int> Config::is_autoindex_on(const ServerConfig &server_config,
                                          const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    LocationConfig location = location_result.get_ok_value();
    return Result<bool, int>::ok(location.autoindex);
}


Result<bool, int> Config::is_autoindex_on(const ServerInfo &server_info,
                                          const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_autoindex_on(server_config, target_path);
}


Result<bool, int> Config::is_autoindex_on(const AddressPortPair &address_port_pair,
                                          const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_autoindex_on(server_config, target_path);
}


Result<LimitExceptDirective, int> Config::limit_except(const ServerConfig &server_config,
                                                       const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<LimitExceptDirective, int>::err(ERR);
    }

    LocationConfig location_config = location_result.get_ok_value();
    LimitExceptDirective &limit_except = location_config.limit_except;
    return Result<LimitExceptDirective, int>::ok(limit_except);
}


Result<bool, int> Config::is_method_allowed(const ServerConfig &server_config,
                                            const std::string &target_path,
                                            const Method &method) {
    Result<LimitExceptDirective, int> result = Config::limit_except(server_config, target_path);
    if (result.is_err()) {
        return Result<bool, int>::err(ERR);
    }

    LimitExceptDirective directive = result.get_ok_value();
    if (!directive.limited) {
        return Result<bool, int>::ok(true);
    }
    bool is_method_allowed = (directive.excluded_methods.find(method) != directive.excluded_methods.end());
    return Result<bool, int>::ok(is_method_allowed);
}


Result<bool, int> Config::is_method_allowed(const ServerInfo &server_info,
                                            const std::string &target_path,
                                            const Method &method) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_method_allowed(server_config, target_path, method);
}


Result<bool, int> Config::is_method_allowed(const AddressPortPair &address_port_pair,
                                            const std::string &target_path,
                                            const Method &method) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_method_allowed(server_config, target_path, method);
}


// todo: server block ?
Result<bool, int> Config::is_redirect(const ServerConfig &server_config,
                                      const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }

    LocationConfig location_config = location_result.get_ok_value();
    ReturnDirective redirection = location_config.redirection;
    return Result<bool, int>::ok(redirection.return_on);
}


Result<bool, int> Config::is_redirect(const ServerInfo &server_info,
                                      const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_redirect(server_config, target_path);
}


Result<bool, int> Config::is_redirect(const AddressPortPair &address_port_pair,
                                      const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_redirect(server_config, target_path);
}


Result<ReturnDirective, int> Config::get_redirect(const ServerConfig &server_config,
                                                  const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }

    LocationConfig location_config = location_result.get_ok_value();
    ReturnDirective redirection = location_config.redirection;
    return Result<ReturnDirective, int>::ok(redirection);
}


Result<ReturnDirective, int> Config::get_redirect(const ServerInfo &server_info,
                                                  const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_redirect(server_config, target_path);
}


Result<ReturnDirective, int> Config::get_redirect(const AddressPortPair &address_port_pair,
                                                  const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_redirect(server_config, target_path);
}


Result<std::size_t, int> Config::get_max_body_size(const ServerConfig &server_config,
                                                   const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<std::size_t, int>::err(ERR);
    }
    LocationConfig location = location_result.get_ok_value();
    return Result<std::size_t, int>::ok(location.max_body_size_bytes);
}


Result<std::size_t, int> Config::get_max_body_size(const ServerInfo &server_info,
                                                   const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::size_t, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_max_body_size(server_config, target_path);
}


Result<std::size_t, int> Config::get_max_body_size(const AddressPortPair &address_port_pair,
                                                   const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::size_t, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_max_body_size(server_config, target_path);
}


Result<bool, int> Config::is_cgi_mode_on(const ServerConfig &server_config,
                                         const std::string &target_path) {
    // std::cout << CYAN << "path: " << target_path << RESET << std::endl;
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        // std::cout << CYAN << "location error" << RESET << std::endl;
        return Result<bool, int>::err(ERR);
    }
    LocationConfig location = location_result.get_ok_value();
    // std::cout << CYAN << "ok -> cgi_mode: "  << (location.cgi.is_cgi_mode ? "on": "off") << RESET << std::endl;
    return Result<bool, int>::ok(location.cgi.is_cgi_mode);
}


Result<bool, int> Config::is_cgi_mode_on(const ServerInfo &server_info,
                                         const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_cgi_mode_on(server_config, target_path);
}


Result<bool, int> Config::is_cgi_mode_on(const AddressPortPair &address_port_pair,
                                         const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_cgi_mode_on(server_config, target_path);
}


Result<std::set<std::string>, int> Config::get_cgi_extension(const ServerConfig &server_config,
                                                             const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return Result<std::set<std::string>, int>::err(ERR);
    }
    LocationConfig location = location_result.get_ok_value();
    return Result<std::set<std::string>, int>::ok(location.cgi.extension);
}


Result<std::set<std::string>, int> Config::get_cgi_extension(const ServerInfo &server_info,
                                                             const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::set<std::string>, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_cgi_extension(server_config, target_path);
}


Result<std::set<std::string>, int> Config::get_cgi_extension(const AddressPortPair &address_port_pair,
                                                             const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::set<std::string>, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_cgi_extension(server_config, target_path);
}


bool Config::is_cgi_extension(const ServerConfig &server_config,
                              const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return false;
    }
    LocationConfig location = location_result.get_ok_value();
    std::string extension = StringHandler::get_extension(target_path);
    if (extension.empty()) {
        return false;
    }
    return location.cgi.extension.find(extension) != location.cgi.extension.end();
}


bool Config::is_cgi_extension(const ServerInfo &server_info,
                              const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return false;
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_cgi_extension(server_config, target_path);
}


bool Config::is_cgi_extension(const AddressPortPair &address_port_pair,
                              const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return false;
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return is_cgi_extension(server_config, target_path);
}


time_t Config::get_cgi_timeout(const ServerConfig &server_config,
                               const std::string &target_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, target_path);
    if (location_result.is_err()) {
        return ConfigInitValue::kDefaultCgiTimeoutSec;
    }
    LocationConfig location = location_result.get_ok_value();
    return location.cgi.timeout_sec;
}


time_t Config::get_cgi_timeout(const ServerInfo &server_info,
                               const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return ConfigInitValue::kDefaultCgiTimeoutSec;
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_cgi_timeout(server_config, target_path);
}


time_t Config::get_cgi_timeout(const AddressPortPair &address_port_pair,
                               const std::string &target_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return ConfigInitValue::kDefaultCgiTimeoutSec;
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_cgi_timeout(server_config, target_path);
}
