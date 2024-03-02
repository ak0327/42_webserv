#pragma once

#include <stdexcept>

template <typename OkType, typename ErrType>
class Result {
 public:
	Result()
		: is_ok_(false),
          ok_value_(OkType()),
          err_value_(ErrType()) {}

	Result(const Result& other)
		: is_ok_(other.is_ok_),
          ok_value_(other.ok_value_),
          err_value_(other.err_value_) {}

	~Result() {}

	Result &operator=(const Result &rhs) {
		if (this == &rhs) {
			return *this;
		}
        is_ok_ = rhs.is_ok_;
        ok_value_ = rhs.ok_value_;
        err_value_ = rhs.err_value_;
		return *this;
	}

	static Result ok(const OkType &value) {
		Result res;
		res.is_ok_ = true;
		res.ok_value_ = value;
		return res;
	}

	static Result err(const ErrType &value) {
		Result res;
		res.is_ok_ = false;
		res.err_value_ = value;
		return res;
	}

	bool is_ok() const { return is_ok_; }
	bool is_err() const { return !is_ok_; }

	OkType ok_value() const {
		if (is_ok_) {
			return ok_value_;
		}
		throw std::runtime_error("[Result Error] Result is not OK");
	}

	ErrType err_value() const {
		if (!is_ok_) {
			return err_value_;
		}
		throw std::runtime_error("[Result Error] Result is not ERROR");
	}

 private:
	bool is_ok_;
	OkType ok_value_;
	ErrType err_value_;
};
