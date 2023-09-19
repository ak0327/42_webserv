#pragma once

#include <stdexcept>

template <typename OkType, typename ErrType>
class Result {
 public:
	Result() : _is_ok(false), _ok_value(OkType()), _err_value(ErrType()) {}
	~Result() {}

	static Result ok(const OkType &value) {
		Result res;
		res._is_ok = true;
		res._ok_value = value;
		return res;
	}

	static Result err(const ErrType &value) {
		Result res;
		res._is_ok = false;
		res._err_value = value;
		return res;
	}

	bool is_ok() const { return _is_ok; }
	bool is_err() const { return !_is_ok; }

	OkType get_ok_value() const {
		if (_is_ok) {
			return _ok_value;
		}
		throw std::runtime_error("Result is not OK");
	}

	ErrType get_err_value() const {
		if (!_is_ok) {
			return _err_value;
		}
		throw std::runtime_error("Result is not ERROR");
	}

 private:
	bool _is_ok;
	OkType _ok_value;
	ErrType _err_value;
};
