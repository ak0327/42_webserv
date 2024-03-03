#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "HttpResponse.hpp"
#include "StringHandler.hpp"


bool HttpResponse::is_logged_in_user() {
    Result<std::map<std::string, std::string>, ProcResult> result = this->request_.get_cookie();
    if (result.is_err()) {
        return false;
    }
    std::map<std::string, std::string> cookies = result.ok_value();

    std::map<std::string, std::string>::const_iterator user, email;
    user = cookies.find("username");
    email = cookies.find("email");
    return user != cookies.end() && email != cookies.end();
}


std::string HttpResponse::get_user_name() {
    Result<std::map<std::string, std::string>, ProcResult> result = this->request_.get_cookie();
    if (result.is_err()) {
        return EMPTY;
    }
    std::map<std::string, std::string> cookies = result.ok_value();

    std::map<std::string, std::string>::const_iterator user;
    user = cookies.find("username");
    if (user == cookies.end()) {
        return EMPTY;
    }
    return user->second;
}


StatusCode HttpResponse::get_cookie_user_page() {
    if (is_logged_in_user()) {
        const std::string head = "<!doctype html>\n"
                                 "<html lang=\"ja\">\n"
                                 "<head>\n"
                                 "    <meta charset=\"UTF-8\">\n"
                                 "    <title>Login page</title>\n"
                                 "</head>\n"
                                 "<body>\n"
                                 "<h1>🍪 Login Page 🍪</h1>\n";

        const std::string welcome = "<h2>Welcome, " + get_user_name() + "</h2>";

        const std::string tail = "<br><br><br>\n"
                                 "<a href=\"/\">< back to index</a>"
                                 "</body>\n"
                                 "</html>\n";

        std::vector<unsigned char> body;
        body.insert(body.end(), head.begin(), head.end());
        body.insert(body.end(), welcome.begin(), welcome.end());
        body.insert(body.end(), tail.begin(), tail.end());
        this->body_buf_ = body;

        add_content_header("html");
        return StatusOk;
    } else {
        ReturnDirective redirect_to_login;
        redirect_to_login.return_on = true;
        redirect_to_login.code = Found;
        redirect_to_login.text = "/login_cookie.html";
        return get_redirect_content(redirect_to_login);
    }
}


StatusCode HttpResponse::get_cookie_login_page() {
    switch (this->request_.method()) {
        case kGET: {
            return get_cookie_user_page();
        }
        case kPOST: {
            UrlEncodedFormData parameters = parse_urlencoded_form_data(this->body_buf_);

            std::map<std::string, std::string> cookies;
            for (UrlEncodedFormData::const_iterator itr = parameters.begin(); itr != parameters.end(); ++itr) {
                if (itr->first == "username") {
                    cookies["username"] = *itr->second.begin();
                }
                if (itr->first == "email") {
                    cookies["email"] = *itr->second.begin();
                }
            }

            this->cookies_ = cookies;
            add_content_header("html");

            ReturnDirective redirect_to_userpage;
            redirect_to_userpage.return_on = true;
            redirect_to_userpage.code = Found;
            redirect_to_userpage.text = "/api/cookie-userpage";
            return get_redirect_content(redirect_to_userpage);
        }
        default: {
            return MethodNotAllowed;
        }
    }
}
