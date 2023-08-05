#include "../includes/ErrorPage.hpp"

ErrorPage::ErrorPage()
{

}

ErrorPage::~ErrorPage()
{

}

ErrorPage::ErrorPage(ErrorPage const &other)
{
	this->changed_statuscode = other.changed_statuscode;
	this->redirect_path = other.redirect_path;
	this->tgt_statuscode = other.tgt_statuscode;
}

ErrorPage& ErrorPage::operator=(ErrorPage const &other)
{
	this->changed_statuscode = other.changed_statuscode;
	this->redirect_path = other.redirect_path;
	this->tgt_statuscode = other.tgt_statuscode;

	return (*this);
}

ErrorPage& ErrorPage::operator=(ErrorPage &other)
{
	this->changed_statuscode = other.changed_statuscode;
	this->redirect_path = other.redirect_path;
	this->tgt_statuscode = other.tgt_statuscode;

	return (*this);
}

void ErrorPage::set_changed_stutsucode(std::vector<std::string> const &status_code_set)
{
	this->changed_statuscode = status_code_set;
}

void ErrorPage::set_target_statuscode(std::string const &target_statuscode)
{
	this->tgt_statuscode = target_statuscode;
}

void ErrorPage::set_redirect_path(std::string const &redirect_path)
{
	this->redirect_path = redirect_path;
}

std::vector<std::string> ErrorPage::get_changed_stutsucode() const
{
	return (this->changed_statuscode);
}

std::string ErrorPage::get_target_statuscode() const
{
	return (this->tgt_statuscode);
}

std::string ErrorPage::get_redirect_path() const
{
	return (this->redirect_path);
}

void ErrorPage::show_wrrorpage_infos()
{
	
}