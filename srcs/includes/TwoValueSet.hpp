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
		TwoValueSet(const std::string &value);
		~TwoValueSet();

		void	set_firstvalue(const std::string &value);
		void	set_secondvalue(const std::string &value);

		std::string get_firstvalue(void) const;
		std::string get_secondvalue(void) const;
};

#endif