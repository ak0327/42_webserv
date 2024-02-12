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


Result<int, std::string> Configuration::get_result() { return this->result_; }


const std::vector<ServerConfig> &Configuration::get_server_configs() const {
    return this->http_config_.servers;
}
