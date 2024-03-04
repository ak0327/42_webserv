#pragma once

# include <map>
# include <string>

class Session {
 public:
    Session();
    Session(const std::string &id,
            const std::map<std::string, std::string> &data,
            time_t timeout_sec);
    Session(const Session &other);
    Session &operator=(const Session &rhs);
    ~Session();

    static std::string generate_hash();
    std::size_t is_empty() const;

    std::string id() const;
    std::map<std::string, std::string> data() const;
    time_t expire_time() const;
    bool is_expired() const;

    void add_data(const std::string &key, const std::string &value);
    void del_data(const std::string &key);
    void update_id(const std::string &new_id);
    void update_expire(time_t new_expire);
    void overwrite_data(const std::map<std::string, std::string> &new_data);
    void clear_data();

 private:
    std::string id_;
    std::map<std::string, std::string> data_;
    time_t expire_time_;
};
