#include "ErrorPage.hpp"

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

#define RESET_COLOR "\033[0m"
#define RED_COLOR "\033[31m"
#define GREEN_COLOR "\033[32m"
#define YELLOW_COLOR "\033[33m"
#define BLUE_COLOR "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR "\033[36m"

void ErrorPage::show_wrrorpage_infos()
{
	std::cout << "changed status code is " << BLUE_COLOR;
	// HandlingString::show_vector_contents(this->changed_statuscode);
	std::cout << RESET_COLOR << std::endl;
	if (this->tgt_statuscode != "")
		std::cout << "target statuscode is " << BLUE_COLOR << this->tgt_statuscode << RESET_COLOR << std::endl;
	else
		std::cout << "target statuscode is " << BLUE_COLOR << "* NO TARGET STATUS CODE *" << RESET_COLOR << std::endl;
	if (this->redirect_path != "")
		std::cout << "redirect path is " << BLUE_COLOR << this->redirect_path << RESET_COLOR << std::endl;
	else
		std::cout << "redirect path is " << BLUE_COLOR << "* NO REDIRECT PATH *" << RESET_COLOR << std::endl;
}
