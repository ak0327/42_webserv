#ifndef TWOVALUESET_HPP
#define TWOVALUESET_HPP

#include <string>
#include <iostream>
#include "BaseKeyValueMap.hpp"

class TwoValueSet: public BaseKeyValueMap
{
	private:
		std::string _firstvalue;
		std::string _secondValue;

		TwoValueSet& operator=(const TwoValueSet &other);
	
	public:
		TwoValueSet();
		TwoValueSet(std::string const &first_value);
		TwoValueSet(const std::string &first_value, const std::string &second_value);
		TwoValueSet& operator=(const TwoValueSet &other);
		~TwoValueSet();

		std::string get_firstvalue(void) const;
		std::string get_secondvalue(void) const;

		void	show_allvalue(void) const;
};

#endif