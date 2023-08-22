#ifndef TWOVALUESET_HPP
#define TWOVALUESET_HPP

class TwoValueSet
{
	private:
		std::string _firstvalue;
		std::string _secondValue;

		TwoValueSet(const TwoValueSet &other);
		TwoValueSet& operator=(const TwoValueSet &other);
	
	public:
		TwoValueSet();
		~TwoValueSet();

		void	set_values(const std::string &first_value, const std::string &second_value);
		void	set_values(const std::string &first_value);

		std::string get_firstvalue(void) const;
		std::string get_secondvalue(void) const;
};

#endif