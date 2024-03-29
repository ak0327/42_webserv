#pragma once

# include <map>
# include <set>
# include <string>
# include <utility>
# include <vector>
# include "Constant.hpp"

namespace ConfigInitValue {

const std::size_t KB = 1024;
const std::size_t MB = KB * KB;
const std::size_t GB = KB * KB * KB;
const std::size_t kDefaultBodySize = 1 * MB;

const time_t kDefaultCgiTimeoutSec = 5;
const time_t kMinCgiTimeoutSec = 1;
const time_t kMaxCgiTImeoutSec = 3600;

const time_t kDefaultSessionTimeoutSec = 60;
const time_t kMinSessionTimeoutSec = 1;
const time_t kMaxSessionTimeoutSec = 3600;

const time_t kDefaultCookieTimeoutSec = 60;

const time_t kDefaultKeepaliveTimeoutSec = 75;
const time_t kMinKeepaliveTimeoutSec = 0;
const time_t kMaxKeepaliveTimeoutSec = 3600;

const time_t kDefaultRecvTimeoutSec = 60;
const time_t kMinRecvTimeoutSec = 1;
const time_t kMaxRecvTimeoutSec = 120;

const time_t kDefaultSendTimeoutSec = 60;
const time_t kMinSendTimeoutSec = 1;
const time_t kMaxSendTimeoutSec = 120;


const char kDefaultRoot[] = "html";
const char kDefaultIndex[] = "index.html";
const char kDefaultAddress[] = "*";
const char kDefaultPort[] = "80";
const char kDefaultServerName[] = "";

const bool kDefaultAutoindex = false;
const bool kDefaultCgiMode = false;
const bool kDefaultRedirectOn = false;

}  // namespace ConfigInitValue


// typedef int StatusCode;
typedef std::string LocationPath;
typedef std::pair<std::string, std::string> AddressPortPair;
typedef std::pair<std::string, std::string> HostPortPair;


enum AccessControl {
    kALLOW, kDENY
};


struct ServerInfo {
    std::string server_name;
    std::string address;
    std::string port;

    bool operator<(const ServerInfo& other) const {
        if (this->server_name < other.server_name) {
            return true;
        }
        if (other.server_name < this->server_name) {
            return false;
        }
        if (this->address < other.address) {
            return true;
        }
        if (other.address < this->address) {
            return false;
        }
        return this->port < other.port;
    }
    ServerInfo()
        : server_name(),
          address(),
          port() {}

    ServerInfo(const std::string &server_name,
               const std::string &address,
               const std::string &port)
        : server_name(server_name),
          address(address),
          port(port) {}
};

struct AccessRule {
    AccessControl control;
    std::string specifier;

    AccessRule(AccessControl control, const std::string &specifier)
        : control(control),
          specifier(specifier) {}
};

struct ListenDirective {
    std::string address;
    std::string port;
    bool is_default_server;

    ListenDirective()
        : address(ConfigInitValue::kDefaultAddress),
          port(ConfigInitValue::kDefaultPort),
          is_default_server(false) {}

    ListenDirective(const std::string &address,
                    const std::string &port,
                    const bool is_default_server)
        : address(address),
          port(port),
          is_default_server(is_default_server) {}

    bool operator<(const ListenDirective& rhs) const {
        if (this->address < rhs.address) {
            return true;
        }
        if (rhs.address < this->address) {
            return false;
        }
        return this->port < rhs.port;
    }
};

struct LimitExceptDirective {
    bool limited;
    std::set<Method> excluded_methods;
    std::vector<AccessRule> rules;

    LimitExceptDirective()
        : limited(false),
          excluded_methods(),
          rules() {}
};


// return directive: location内部のみとする
struct ReturnDirective {
    bool return_on;
    StatusCode code;
    std::string text;

    ReturnDirective()
        : return_on(ConfigInitValue::kDefaultRedirectOn),
          code(),
          text() {}
};

struct CgiDirectove {
    bool is_cgi_mode;
    std::set<std::string> extension;
    time_t timeout_sec;

    CgiDirectove()
        : is_cgi_mode(ConfigInitValue::kDefaultCgiMode),
          extension(),
          timeout_sec(ConfigInitValue::kDefaultCgiTimeoutSec) {}
};

struct DefaultConfig {
    std::string root_path;
    std::set<std::string> index_pages;
    std::map<StatusCode, std::string> error_pages;
    bool autoindex;
    std::size_t max_body_size_bytes;

    DefaultConfig()
        : root_path(ConfigInitValue::kDefaultRoot),
          index_pages(),
          error_pages(),
          autoindex(ConfigInitValue::kDefaultAutoindex),
          max_body_size_bytes(1 * ConfigInitValue::MB){
        index_pages.insert(ConfigInitValue::kDefaultIndex);
    }
};

struct LocationConfig : public DefaultConfig {
    ReturnDirective redirection;  // can't use string `return`
    LimitExceptDirective limit_except;
    CgiDirectove cgi;

    LocationConfig()
            : redirection(),
              limit_except(),
              cgi() {}

    explicit LocationConfig(const DefaultConfig &other)
            : DefaultConfig(other),
              redirection(),
              limit_except(),
              cgi(){}
};

struct ServerConfig : public DefaultConfig  {
    std::vector<ListenDirective> listens;
    std::set<std::string> server_names;
    std::map<LocationPath, LocationConfig> locations;

    time_t session_timeout_sec;

    ServerConfig()
        : listens(),
          server_names(),
          locations(),
          session_timeout_sec(ConfigInitValue::kDefaultSessionTimeoutSec) {}
};

struct HttpConfig {
    std::vector<ServerConfig> servers;
    time_t recv_timeout_sec;
    time_t send_timeout_sec;
    time_t keepalive_timeout_sec;

    HttpConfig()
        : servers(),
          recv_timeout_sec(ConfigInitValue::kDefaultRecvTimeoutSec),
          send_timeout_sec(ConfigInitValue::kDefaultSendTimeoutSec),
          keepalive_timeout_sec(ConfigInitValue::kDefaultKeepaliveTimeoutSec) {}
};
