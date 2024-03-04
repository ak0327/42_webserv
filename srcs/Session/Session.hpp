#pragma once

# include <map>
# include <string>

class Session {
 public:
    Session();
    Session(const Session &other);
    Session &operator=(const Session &rhs);
    ~Session();

    std::string generate_hash();
    std::map<std::string, std::string> data() const;
    std::size_t is_empty() const;

    void add_data(const std::string &key, const std::string &value);
    void del_data(const std::string &key);
    void overwrite_data(const std::map<std::string, std::string> &new_data);
    void clear_data();

 private:
    std::map<std::string, std::string> data_;
    time_t expire_time_;
};
