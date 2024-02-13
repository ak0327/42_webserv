#include <fstream>
#include "webserv.hpp"
#include "Configuration.hpp"
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Token.hpp"
#include "Parser.hpp"

Configuration::Configuration(const char *file_path) {
	Parser parser;
	Result<int, std::string> parse_result;
	std::string error_msg;

	parser = Parser(file_path);
	parse_result = parser.get_result();
	if (parse_result.is_err()) {
		error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

    this->http_config_ = parser.get_config();
    set_server_configs();

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


Result<int, std::string> Configuration::get_result() { return this->result_; }


const std::map<ServerInfo, const ServerConfig *> &Configuration::get_server_configs() const {
    return this->server_configs_;
}
