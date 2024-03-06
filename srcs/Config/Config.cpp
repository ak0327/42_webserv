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
    if (parser.is_err()) {
		const std::string error_msg = parser.result().err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
    }

    this->http_config_ = parser.config();
    set_server_configs();
    Result<int, std::string> result = set_default_servers();
    if (result.is_err()) {
        const std::string error_msg = result.err_value();
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


bool Config::is_err() const { return this->result_.is_err(); }


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
        const std::string error_msg = result.err_value();
        return Result<int, std::string>::err(error_msg);
    }

    set_default_server_to_first_listen();

    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Config::result() const { return this->result_; }


time_t Config::keepalive_timeout() const { return this->http_config_.keepalive_timeout_sec; }
time_t Config::recv_timeout() const { return this->http_config_.recv_timeout_sec; }
time_t Config::send_timeout() const { return this->http_config_.send_timeout_sec; }
