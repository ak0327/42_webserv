#pragma once

# include <string>
# include "Constant.hpp"
# include "FieldValueBase.hpp"
# include "Result.hpp"

class Date : public FieldValueBase {
 public:
	explicit Date(const std::string &http_date);
	Date(const Date &other);
	Date &operator=(const Date &rhs);
	virtual ~Date();

	std::string get_day_name() const;
	std::string get_day() const;
	std::string get_month() const;
	std::string get_year() const;
	std::string get_hour() const;
	std::string get_minute() const;
	std::string get_second() const;
	std::string get_gmt() const;
	date_format get_format() const;
	bool is_ok() const;
	bool is_err() const;

    bool operator==(const Date &rhs) const;
    bool operator<(const Date &rhs) const;
    bool operator>(const Date &rhs) const;
    bool operator<=(const Date &rhs) const;

 private:
	std::string	day_name_;
	std::string day_;
	std::string month_;
	std::string year_;
	std::string hour_;
	std::string minute_;
	std::string second_;
	std::string gmt_;
	date_format format_;
	Result<int, int> result_;
};
