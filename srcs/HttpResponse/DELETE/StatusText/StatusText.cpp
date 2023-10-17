#include "StatusText.hpp"

StatusText::StatusText(const std::string &status_text, const std::string &body_text)
{
	this->_status_text = status_text;
	this->_body_text = body_text;
}

StatusText::~StatusText(){}

StatusText::get_status_text(){ return (this->_status_text); }
StatusText::get_body_text(){ return (this->get_body_text); }
