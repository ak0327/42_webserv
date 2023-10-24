#pragma once

# include <map>
# include <string>
# include "FieldValueBase.hpp"
# include "Result.hpp"

class MediaType : public FieldValueBase {
 public:
	MediaType();
	explicit MediaType(const std::string &field_value);
	MediaType(const std::string &type,
			  const std::string &subtype,
			  const std::map<std::string, std::string> &parameters);
	virtual ~MediaType();

	MediaType(const MediaType &other);
	MediaType &operator=(const MediaType &rhs);

	std::string get_type() const;
	std::string get_subtype() const;
	std::map<std::string, std::string> get_parameters() const;

	bool is_ok() const;
	bool is_err() const;

 private:
	std::string _type;
	std::string _subtype;
	std::map<std::string, std::string> _parameters;
	Result<int, int> _result;

	Result<int, int> parse(const std::string &field_value);
	Result<int, int> validate();
};
