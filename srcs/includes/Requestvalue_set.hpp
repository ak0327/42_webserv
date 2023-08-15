#ifndef REQUESTVALUE_SET_HPP
#define REQUESTVALUE_SET_HPP

#include <string>

class Requestvalue_set
{
	private:
		std::string	_value;
		double		_weight;
	
	public:
		Requestvalue_set();
		Requestvalue_set(const std::string &other);
		Requestvalue_set(const Requestvalue_set &other);
		Requestvalue_set &operator=(const Requestvalue_set &other);
		~Requestvalue_set();

		void		clear_membervariable(void);

		std::string	get_value(void) const;
		double		get_weight(void) const;

		void		set_value(const std::string &other);
		void		set_weight(const std::string &other);
		void		set_weight(double other);
};

#endif