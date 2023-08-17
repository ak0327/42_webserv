#include "../includes/Requestvalue_set.hpp"

Requestvalue_set::Requestvalue_set()
{
	this->_value = "";
	this->_weight = 0.0;
}

Requestvalue_set::Requestvalue_set(const std::string &other)
{
	if (other.find(';') == std::string::npos)
	{
		this->_value = other;
		this->_weight = 1.0;
	}
	else
	{
		this->_value = HandlingString::obtain_beforeword(other, ';');
		this->_weight = HandlingString::str_to_double(HandlingString::obtain_afterword(other, ';'));
	}
}

Requestvalue_set::Requestvalue_set(const Requestvalue_set &other)
{
	this->_value = other.get_value();
	this->_weight = other.get_weight();
}

Requestvalue_set& Requestvalue_set::operator=(const Requestvalue_set &other)
{
	if (this == &other)
		return (*this);
	this->_value = other.get_value();
	this->_weight = other.get_weight();
	return (*this);
}

Requestvalue_set::~Requestvalue_set()
{
	//何もない
}

void Requestvalue_set::clear_membervariable()
{
	this->_value = "";
	this->_weight = 0.0;
}

void	Requestvalue_set::set_value(const std::string &other)
{
	this->_value = other;
}

void	Requestvalue_set::set_weight(const std::string &other)
{
	this->_weight = HandlingString::str_to_double(other);
}
void	Requestvalue_set::set_weight(double other)
{
	this->_weight = other;
}

std::string Requestvalue_set::get_value() const
{
	return (this->_value);
}

double Requestvalue_set::get_weight() const
{
	return (this->_weight);
}