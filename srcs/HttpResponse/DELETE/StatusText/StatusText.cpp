#include "StatusText.hpp"

StatusText::StatusText(){}

StatusText::StatusText(const std::string &status_text, const std::string &body_text)
{
	this->_status_text = status_text;
	this->_body_text = body_text;
}

StatusText::~StatusText(){}

std::string StatusText::get_status_text() const { return (this->_status_text); }
std::string StatusText::get_body_text() const { return (this->_body_text); }
