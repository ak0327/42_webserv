#include <fstream>
#include <map>
#include <set>
#include <utility>
#include "webserv.hpp"
#include "Configuration.hpp"
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Token.hpp"
#include "Parser.hpp"

Configuration::Configuration(const char *file_path) {
	Parser parser(file_path);
    Result<int, std::string> parse_result = parser.get_result();
	if (parse_result.is_err()) {
		const std::string error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

    this->http_config_ = parser.get_config();
    set_server_configs();
    Result<int, std::string> result = set_default_servers();
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        this->result_ = Result<int, std::string>::err(error_msg);
        return;
    }
	this->result_ = Result<int, std::string>::ok(OK);
}


Configuration::Configuration(const Configuration &other) {
	*this = other;
}


Configuration::~Configuration() {}


Configuration &Configuration::operator=(const Configuration &rhs) {
	if (this == &rhs) {
		return *this;
	}

	this->http_config_ = rhs.http_config_;
	this->result_ = rhs.result_;
	return *this;
}


void Configuration::set_server_configs() {
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


Result<int, std::string> Configuration::set_default_server_to_default_listen() {
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


void Configuration::set_default_server_to_first_listen() {
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


Result<int, std::string> Configuration::set_default_servers() {
    Result<int, std::string> result = set_default_server_to_default_listen();
    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return Result<int, std::string>::err(error_msg);
    }

    set_default_server_to_first_listen();

    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Configuration::get_result() const { return this->result_; }


std::map<ServerInfo, const ServerConfig *> Configuration::get_server_configs() const {
    return this->server_configs_;
}


Result<ServerConfig, int> Configuration::get_server_config(const ServerInfo &server_info) const {
    std::map<ServerInfo, const ServerConfig *>::const_iterator server_config;
    server_config = this->server_configs_.find(server_info);

    if (server_config != this->server_configs_.end()) {
        return Result<ServerConfig, int>::ok(*server_config->second);
    } else {
        AddressPortPair pair(server_info.address, server_info.port);
        return get_default_server(pair);
    }
}


Result<ServerConfig, int> Configuration::get_default_server(const AddressPortPair &pair) const {
    std::map<AddressPortPair, const ServerConfig *> ::const_iterator default_server;
    default_server = this->default_servers_.find(pair);

    if (default_server != this->default_servers_.end()) {
        return Result<ServerConfig, int>::ok(*default_server->second);
    } else {
        return Result<ServerConfig, int>::err(ERR);
    }
}


Result<LocationConfig, int> Configuration::get_location_config(const ServerConfig &server_config,
                                                               const std::string &location_path) {
    std::map<LocationPath, LocationConfig>::const_iterator location;
    location = server_config.locations.find(location_path);
    if (location == server_config.locations.end()) {
        return Result<LocationConfig, int>::err(ERR);
    }
    return Result<LocationConfig, int>::ok(location->second);
}


std::string Configuration::get_root(const ServerConfig &server_config,
                                    const std::string &location_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_ok()) {
        LocationConfig location = location_result.get_ok_value();
        return location.root_path;
    }
    return server_config.root_path;
}


Result<std::string, int> Configuration::get_root(const ServerInfo &server_info,
                                                 const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::string, int>::ok(get_root(server_config, location_path));
}


Result<std::string, int> Configuration::get_root(const AddressPortPair &address_port_pair,
                                                 const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::string, int>::ok(get_root(server_config, location_path));
}


std::string Configuration::get_index(const ServerConfig &server_config,
                                     const std::string &location_path) {
    std::set<std::string> index_pages;

    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_ok()) {
        LocationConfig location_config = location_result.get_ok_value();
        index_pages = location_config.index_pages;
    } else {
        index_pages = server_config.index_pages;
    }

    const std::string root = get_root(server_config, location_path);
    for (std::set<std::string>::const_iterator page = index_pages.begin(); page != index_pages.end(); ++page) {
        const std::string path = root + "/" + *page;
        std::ifstream ifs(path.c_str());

        if (ifs.is_open()) {
            return *page;
        }
        ifs.close();
    }
    return ConfigInitValue::kDefaultIndex;
}


Result<std::string, int> Configuration::get_index(const ServerInfo &server_info,
                                                  const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::string, int>::ok(get_index(server_config, location_path));
}


Result<std::string, int> Configuration::get_index(const AddressPortPair &address_port_pair,
                                                  const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::string, int>::ok(get_index(server_config, location_path));
}


Result<std::string, int> Configuration::get_error_page(const ServerConfig &server_config,
                                                       const std::string &location_path,
                                                       const StatusCode &code) {
    std::map<StatusCode, std::string> error_pages;

    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_ok()) {
        LocationConfig location_config = location_result.get_ok_value();
        error_pages = location_config.error_pages;
    } else {
        error_pages = server_config.error_pages;
    }

    if (error_pages.find(code) == error_pages.end()) {
        return Result<std::string, int>::err(ERR);
    }
    return Result<std::string, int>::ok(error_pages[code]);
}


Result<std::string, int> Configuration::get_error_page(const ServerInfo &server_info,
                                                       const std::string &location_path,
                                                       const StatusCode &code) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_error_page(server_config, location_path, code);
}


Result<std::string, int> Configuration::get_error_page(const AddressPortPair &address_port_pair,
                                                       const std::string &location_path,
                                                       const StatusCode &code) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::string, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_error_page(server_config, location_path, code);
}


bool Configuration::is_autoindex_on(const ServerConfig &server_config,
                                    const std::string &location_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_ok()) {
        LocationConfig location = location_result.get_ok_value();
        return location.autoindex;
    }
    return server_config.autoindex;
}


Result<bool, int> Configuration::is_autoindex_on(const ServerInfo &server_info,
                                    const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_autoindex_on(server_config, location_path));
}


Result<bool, int> Configuration::is_autoindex_on(const AddressPortPair &address_port_pair,
                                    const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_autoindex_on(server_config, location_path));
}


bool Configuration::is_method_allowed(const ServerConfig &server_config,
                                      const std::string &location_path,
                                      const Method &method) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_err()) {
        return true;
    }

    LocationConfig location_config = location_result.get_ok_value();
    LimitExceptDirective &limit_except = location_config.limit_except;
    std::set<Method> &excluded_methods = limit_except.excluded_methods;

    // todo: deny, accept
    if (excluded_methods.empty()) {
        return true;
    }
    return excluded_methods.find(method) != excluded_methods.end();
}


Result<bool, int> Configuration::is_method_allowed(const ServerInfo &server_info,
                                      const std::string &location_path,
                                      const Method &method) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_method_allowed(server_config, location_path, method));
}


Result<bool, int> Configuration::is_method_allowed(const AddressPortPair &address_port_pair,
                                      const std::string &location_path,
                                      const Method &method) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_method_allowed(server_config, location_path, method));
}


// todo: server block ?
bool Configuration::is_redirect(const ServerConfig &server_config,
                                const std::string &location_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_err()) {
        return false;
    }

    LocationConfig location_config = location_result.get_ok_value();
    ReturnDirective redirection = location_config.redirection;
    return redirection.return_on;
}


Result<bool, int> Configuration::is_redirect(const ServerInfo &server_info,
                                             const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_redirect(server_config, location_path));
}


Result<bool, int> Configuration::is_redirect(const AddressPortPair &address_port_pair,
                                             const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<bool, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<bool, int>::ok(is_redirect(server_config, location_path));
}


Result<ReturnDirective, int> Configuration::get_redirect(const ServerConfig &server_config,
                                                         const std::string &location_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }

    LocationConfig location_config = location_result.get_ok_value();
    ReturnDirective redirection = location_config.redirection;
    if (!redirection.return_on) {
        return Result<ReturnDirective, int>::err(ERR);
    }
    return Result<ReturnDirective, int>::ok(redirection);
}


Result<ReturnDirective, int> Configuration::get_redirect(const ServerInfo &server_info,
                                                         const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_redirect(server_config, location_path);
}


Result<ReturnDirective, int> Configuration::get_redirect(const AddressPortPair &address_port_pair,
                                                         const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<ReturnDirective, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return get_redirect(server_config, location_path);
}


std::size_t Configuration::get_max_body_size(const ServerConfig &server_config,
                                             const std::string &location_path) {
    Result<LocationConfig, int> location_result = get_location_config(server_config, location_path);
    if (location_result.is_ok()) {
        LocationConfig location = location_result.get_ok_value();
        return location.max_body_size_bytes;
    }
    return server_config.max_body_size_bytes;
}


Result<std::size_t, int> Configuration::get_max_body_size(const ServerInfo &server_info,
                                             const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_server_config(server_info);
    if (server_config_result.is_err()) {
        return Result<std::size_t, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::size_t, int>::ok(get_max_body_size(server_config, location_path));
}


Result<std::size_t, int> Configuration::get_max_body_size(const AddressPortPair &address_port_pair,
                                             const std::string &location_path) const {
    Result<ServerConfig, int> server_config_result = get_default_server(address_port_pair);
    if (server_config_result.is_err()) {
        return Result<std::size_t, int>::err(ERR);
    }
    ServerConfig server_config = server_config_result.get_ok_value();
    return Result<std::size_t, int>::ok(get_max_body_size(server_config, location_path));
}
