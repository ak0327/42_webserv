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


Result<int, std::string> Configuration::get_result() { return this->result_; }


const std::map<ServerInfo, const ServerConfig *> &Configuration::get_server_configs() const {
    return this->server_configs_;
}


const ServerConfig &Configuration::get_server_config(const ServerInfo &server_info) const {
    std::map<ServerInfo, const ServerConfig *>::const_iterator server_config;
    server_config = this->server_configs_.find(server_info);

    if (server_config != this->server_configs_.end()) {
        return *server_config->second;
    } else {
        AddressPortPair pair(server_info.address, server_info.port);
        return get_default_server(pair);
    }
}


const ServerConfig &Configuration::get_default_server(const AddressPortPair &pair) const {
    std::map<AddressPortPair, const ServerConfig *> ::const_iterator default_server;
    default_server = this->default_servers_.find(pair);

    if (default_server != this->default_servers_.end()) {
        return *default_server->second;
    } else {
        return *this->server_configs_.begin()->second;  // todo: tmp
    }
}
