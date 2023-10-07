#include "HttpRequest.hpp"

ValueDateSet* HttpRequest::ready_ValueDateSet(const std::string &value)
{
	return (new ValueDateSet(StringHandler::obtain_withoutows_value(value)));
}

// dateクラス
void	HttpRequest::set_date(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			day_name;
	std::string			day;
	std::string			month;
	std::string			year;
	std::string			hour;
	std::string			minute;
	std::string			second;

	std::getline(ss, day_name, ',');
	std::getline(ss, line, ',');
	if (day_name != "Mon" && day_name != "Tue" && day_name != "Wed" && day_name != "Thu" && day_name != "Fri" && day_name != "Sat" && day_name != "Sun")
		return;
	std::string after_line = line.substr(1);
	std::stringstream	sss(after_line);
	std::getline(sss, day, ' ');
	if (day.length() != 2)
		return;
	if (!(1 <= StringHandler::str_to_int(day) || StringHandler::str_to_int(day) <= 31))
		return;
	std::getline(sss, month, ' ');
	std::getline(sss, year, ' ');
	std::string			hour_minute_second;
	std::getline(sss, hour_minute_second, ' ');
	std::stringstream	ssss(hour_minute_second);
	std::getline(ssss, hour, ':');
	if (!(0 <= StringHandler::str_to_int(hour) || StringHandler::str_to_int(hour) <= 60))
		return;
	std::getline(ssss, minute, ':');
	if (!(0 <= StringHandler::str_to_int(minute) || StringHandler::str_to_int(minute) <= 60))
		return;
	std::getline(ssss, second, ':');
	if (!(0 <= StringHandler::str_to_int(second) || StringHandler::str_to_int(second) <= 60))
		return;
	this->_request_keyvalue_map[key] = this->ready_ValueDateSet(value);
}

void	HttpRequest::set_if_modified_since(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			day_name;
	std::string			day;
	std::string			month;
	std::string			year;
	std::string			hour;
	std::string			minute;
	std::string			second;

	std::getline(ss, day_name, ',');
	std::getline(ss, line, ',');
	if (day_name != "Mon" && day_name != "Tue" && day_name != "Wed" && day_name != "Thu" && day_name != "Fri" && day_name != "Sat" && day_name != "Sun")
		return;
	std::string after_line = line.substr(1);
	std::stringstream	sss(after_line);
	std::getline(sss, day, ' ');
	if (day.length() != 2)
		return;
	if (!(1 <= StringHandler::str_to_int(day) || StringHandler::str_to_int(day) <= 31))
		return;
	std::getline(sss, month, ' ');
	std::getline(sss, year, ' ');
	std::string			hour_minute_second;
	std::getline(sss, hour_minute_second, ' ');
	std::stringstream	ssss(hour_minute_second);
	std::getline(ssss, hour, ':');
	if (!(0 <= StringHandler::str_to_int(hour) || StringHandler::str_to_int(hour) <= 60))
		return;
	std::getline(ssss, minute, ':');
	if (!(0 <= StringHandler::str_to_int(minute) || StringHandler::str_to_int(minute) <= 60))
		return;
	std::getline(ssss, second, ':');
	if (!(0 <= StringHandler::str_to_int(second) || StringHandler::str_to_int(second) <= 60))
		return;
	this->_request_keyvalue_map[key] = this->ready_ValueDateSet(value);
}

void	HttpRequest::set_if_unmodified_since(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			day_name;
	std::string			day;
	std::string			month;
	std::string			year;
	std::string			hour;
	std::string			minute;
	std::string			second;

	std::getline(ss, day_name, ',');
	std::getline(ss, line, ',');
	if (day_name != "Mon" && day_name != "Tue" && day_name != "Wed" && day_name != "Thu" && day_name != "Fri" && day_name != "Sat" && day_name != "Sun")
		return;
	std::string after_line = line.substr(1);
	std::stringstream	sss(after_line);
	std::getline(sss, day, ' ');
	if (day.length() != 2)
		return;
	if (!(1 <= StringHandler::str_to_int(day) || StringHandler::str_to_int(day) <= 31))
		return;
	std::getline(sss, month, ' ');
	std::getline(sss, year, ' ');
	std::string			hour_minute_second;
	std::getline(sss, hour_minute_second, ' ');
	std::stringstream	ssss(hour_minute_second);
	std::getline(ssss, hour, ':');
	if (!(0 <= StringHandler::str_to_int(hour) || StringHandler::str_to_int(hour) <= 60))
		return;
	std::getline(ssss, minute, ':');
	if (!(0 <= StringHandler::str_to_int(minute) || StringHandler::str_to_int(minute) <= 60))
		return;
	std::getline(ssss, second, ':');
	if (!(0 <= StringHandler::str_to_int(second) || StringHandler::str_to_int(second) <= 60))
		return;
	this->_request_keyvalue_map[key] = this->ready_ValueDateSet(value);
}

void	HttpRequest::set_last_modified(const std::string &key, const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;
	std::string			day_name;
	std::string			day;
	std::string			month;
	std::string			year;
	std::string			hour;
	std::string			minute;
	std::string			second;

	std::getline(ss, day_name, ',');
	std::getline(ss, line, ',');
	if (day_name != "Mon" && day_name != "Tue" && day_name != "Wed" && day_name != "Thu" && day_name != "Fri" && day_name != "Sat" && day_name != "Sun")
		return;
	std::string after_line = line.substr(1);
	std::stringstream	sss(after_line);
	std::getline(sss, day, ' ');
	if (day.length() != 2)
		return;
	if (!(1 <= StringHandler::str_to_int(day) || StringHandler::str_to_int(day) <= 31))
		return;
	std::getline(sss, month, ' ');
	std::getline(sss, year, ' ');
	std::string			hour_minute_second;
	std::getline(sss, hour_minute_second, ' ');
	std::stringstream	ssss(hour_minute_second);
	std::getline(ssss, hour, ':');
	if (!(0 <= StringHandler::str_to_int(hour) || StringHandler::str_to_int(hour) <= 60))
		return;
	std::getline(ssss, minute, ':');
	if (!(0 <= StringHandler::str_to_int(minute) || StringHandler::str_to_int(minute) <= 60))
		return;
	std::getline(ssss, second, ':');
	if (!(0 <= StringHandler::str_to_int(second) || StringHandler::str_to_int(second) <= 60))
		return;
	this->_request_keyvalue_map[key] = this->ready_ValueDateSet(value);
}
