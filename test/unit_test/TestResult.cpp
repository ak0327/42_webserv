#include <climits>
#include <string>
#include "gtest/gtest.h"
#include "Result.hpp"

/* Constructor */
TEST(ResultIntString, Constructor) {
	try {
		Result<int, std::string>res;

		EXPECT_EQ(false, res.is_ok());
		EXPECT_ANY_THROW(res.get_ok_value());

		EXPECT_EQ(true, res.is_err());
		EXPECT_EQ("", res.get_err_value());
	} catch (std::exception const &e) {
		FAIL();
	}
}

/* Result<int, string> */
// ok
TEST(ResultIntString, OkIntPlus) {
	int value = 1;
	Result<int, std::string>res = Result<int, std::string>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

TEST(ResultIntString, OkIntMinus) {
	int value = -1;
	Result<int, std::string>res = Result<int, std::string>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

TEST(ResultIntString, OkIntINTMAX) {
	int value = INT_MAX;
	Result<int, std::string>res = Result<int, std::string>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

TEST(ResultIntString, OkIntINTMIN) {
	int value = INT_MIN;
	Result<int, std::string>res = Result<int, std::string>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

// err
TEST(ResultIntString, Err) {
	std::string msg = "error occurred";
	Result<int, std::string>res = Result<int, std::string>::err(msg);

	EXPECT_EQ(false, res.is_ok());
	EXPECT_ANY_THROW(res.get_ok_value());

	EXPECT_EQ(true, res.is_err());
	EXPECT_EQ(msg, res.get_err_value());
}


/* Result<string, string> */
// ok
TEST(ResultStringString, Ok) {
	std::string msg = "ok";
	Result<std::string, std::string>res = Result<std::string, std::string>::ok(msg);

	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(msg, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

// err
TEST(ResultStringString, Err) {
	std::string msg = "err";
	Result<std::string, std::string>res = Result<std::string, std::string>::err(msg);

	EXPECT_EQ(false, res.is_ok());
	EXPECT_ANY_THROW(res.get_ok_value());

	EXPECT_EQ(true, res.is_err());
	EXPECT_EQ(msg, res.get_err_value());
}


/* Result<int, int> */
// ok
TEST(ResultIntInt, Ok) {
	int value = 0;
	Result<int, int>res = Result<int, int>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());
}

// err
TEST(ResultIntInt, Err) {
	int value = 1;
	Result<int, int>res = Result<int, int>::err(value);

	EXPECT_EQ(false, res.is_ok());
	EXPECT_ANY_THROW(res.get_ok_value());

	EXPECT_EQ(true, res.is_err());
	EXPECT_EQ(value, res.get_err_value());
}

/* assignment */
namespace {
	Result<int, std::string> func_ok(int value) {
		return Result<int, std::string>::ok(value);
	}

	Result<int, std::string> func_err(const std::string &value) {
		return Result<int, std::string>::err(value);
	}
}  // namespace

TEST(ResultIntString, Assignment1) {
	int value = 1;
	Result<int, std::string>res1 = func_ok(value);

	EXPECT_EQ(true, res1.is_ok());
	EXPECT_EQ(value, res1.get_ok_value());

	EXPECT_EQ(false, res1.is_err());
	EXPECT_ANY_THROW(res1.get_err_value());

	std::string msg = "error occurred";
	Result<int, std::string>res2 = func_err(msg);

	EXPECT_EQ(false, res2.is_ok());
	EXPECT_ANY_THROW(res2.get_ok_value());

	EXPECT_EQ(true, res2.is_err());
	EXPECT_EQ(msg, res2.get_err_value());
}

TEST(ResultIntString, Assignment2) {
	int value = 1;
	Result<int, std::string>res;

	res = Result<int, std::string>::ok(value);
	EXPECT_EQ(true, res.is_ok());
	EXPECT_EQ(value, res.get_ok_value());

	EXPECT_EQ(false, res.is_err());
	EXPECT_ANY_THROW(res.get_err_value());

	std::string msg = "error occurred";
	res = func_err(msg);
	EXPECT_EQ(false, res.is_ok());
	EXPECT_ANY_THROW(res.get_ok_value());

	EXPECT_EQ(true, res.is_err());
	EXPECT_EQ(msg, res.get_err_value());
}
