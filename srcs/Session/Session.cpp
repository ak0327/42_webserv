#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include "Color.hpp"
#include "Debug.hpp"
#include "Session.hpp"

Session::Session() {}


Session::Session(const std::string &id,
                 const std::map<std::string, std::string> &data,
                 time_t timeout_sec)
    : id_(id),
      data_(data),
      expire_time_(std::time(NULL) + timeout_sec) {}


Session::~Session() {}


Session::Session(const Session &other) {
    *this = other;
}


Session &Session::operator=(const Session &rhs) {
    if (this == &rhs) {
        return *this;
    }
    this->id_ = rhs.id_;
    this->data_ = rhs.data_;
    this->expire_time_ = rhs.expire_time_;
    return *this;
}


std::string Session::generate_hash() {
    std::ostringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::rand() % 16;
    }
    return ss.str();
}


std::size_t Session::is_empty() const { return this->data_.empty(); }

std::string Session::id() const { return this->id_; }
std::map<std::string, std::string> Session::data() const { return this->data_; }
time_t Session::expire_time() const { return this->expire_time_; }


bool Session::is_expired() const {
    time_t current_time = std::time(NULL);
    return this->expire_time() <= current_time;
}


void Session::update_id(const std::string &new_id) {
    DEBUG_PRINT(MAGENTA, "session update_id [%s]->[%s]", this->id().c_str(), new_id.c_str());
    this->id_ = new_id;
}


void Session::update_expire(time_t timeout_sec) {
    time_t new_expire_time = std::time(NULL) + timeout_sec;
    DEBUG_PRINT(MAGENTA, "session update_expire [%zu]->[%zu]", this->expire_time(), new_expire_time);
    this->expire_time_ = new_expire_time;
}


void Session::overwrite_data(const std::map<std::string, std::string> &new_data) {
    this->data_ = new_data;
}


void Session::clear_data() {
    this->data_.clear();
}


// add key-value pair to data, if key already exists, overwrite value
void Session::add_data(const std::string &key, const std::string &value) {
    this->data_[key] = value;
}


void Session::del_data(const std::string &key) {
    std::map<std::string, std::string>::iterator itr = this->data_.find(key);
    if (itr != this->data_.end()) {
        this->data_.erase(itr);
    }
}
