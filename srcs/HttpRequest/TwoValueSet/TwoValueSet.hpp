#pragma once

# include <string>
# include "FieldValues.hpp"

class TwoValueSet : public FieldValues {
 public:
	TwoValueSet(const std::string &first_value, const std::string &second_value);
	TwoValueSet(const TwoValueSet &other);
	TwoValueSet& operator=(const TwoValueSet &rhs);

	virtual ~TwoValueSet();
	std::string	get_firstvalue(void) const;
	std::string get_secondvalue(void) const;

 private:
	std::string	_firstvalue;
	std::string _secondValue;
};
