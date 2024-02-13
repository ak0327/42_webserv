#pragma once

# include <map>
# include <set>
# include <string>
# include <utility>
# include <vector>

namespace ConfigInitValue {

const std::size_t KB = 1024;
const std::size_t MB = KB * KB;
const std::size_t GB = KB * KB * KB;
const std::size_t kDefaultBodySize = 1 * MB;

const char kDefaultRoot[] = "html";
const char kDefaultIndex[] = "index.html";
const char kDefaultAddress[] = "*";
const char kDefaultPort[] = "80";
const char kDefaultServerName[] = "";

const bool kDefaultAutoindex = false;
const bool kDefaultRedirectOn = false;

}  // namespace ConfigInitValue


typedef int StatusCode;
typedef std::string LocationPath;
typedef std::pair<std::string, std::string> AddressPortPair;

enum Method {
    kGET, kPOST, kDELETE
};

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
    std::set<Method> excluded_methods;
    std::vector<AccessRule> rules;  // allow, deny <- not support in webserv

    LimitExceptDirective()
        : excluded_methods(),
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
          max_body_size_bytes(1 * ConfigInitValue::MB) {
        index_pages.insert(ConfigInitValue::kDefaultIndex);
    }
};

struct LocationConfig : public DefaultConfig {
    ReturnDirective redirection;  // can't use string `return`
    LimitExceptDirective limit_except;

    LocationConfig()
            : redirection(),
              limit_except() {}

    explicit LocationConfig(const DefaultConfig &other)
            : DefaultConfig(other),
              redirection(),
              limit_except() {}
};

struct ServerConfig : public DefaultConfig  {
    std::vector<ListenDirective> listens;
    std::set<std::string> server_names;
    std::map<LocationPath, LocationConfig> locations;

    ServerConfig()
        : listens(),
          server_names(),
          locations() {}
};

struct HttpConfig {
    std::vector<ServerConfig> servers;

    HttpConfig() : servers() {}
};
