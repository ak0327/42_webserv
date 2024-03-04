#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include "Session.hpp"

Session::Session() {}

Session::~Session() {}


Session::Session(const Session &other) {
    *this = other;
}


Session &Session::operator=(const Session &rhs) {
    if (this == &rhs) {
        return *this;
    }
    this->data_ = rhs.data_;
    this->expire_time_ = rhs.expire_time_;
    return *this;
}


std::string Session::generate_hash() {
    std::srand(static_cast<unsigned int>(std::time(NULL)));
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << std::rand() % 16;
    }
    return ss.str();
}


std::map<std::string, std::string> Session::data() const { return this->data_; }
std::size_t Session::is_empty() const { return this->data_.empty(); }


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
