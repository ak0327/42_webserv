#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Date.hpp"
#include "Debug.hpp"
#include "Dynamic.hpp"
#include "HttpResponse.hpp"
#include "StringHandler.hpp"


bool HttpResponse::is_logged_in_user() {
    // std::cout << RED << "is_logged_in_user" << RESET << std::endl;
    Result<std::map<std::string, std::string>, ProcResult> result = this->request_.get_cookie();
    if (result.is_err()) {
        // std::cout << RED << " get_cookie failue" << RESET << std::endl;
        return false;
    }
    std::map<std::string, std::string> cookies = result.ok_value();

    std::map<std::string, std::string>::const_iterator user, email, expire;
    user = cookies.find("username");
    email = cookies.find("email");
    if (user == cookies.end() || email == cookies.end()) {
        return false;
    }
    expire = cookies.find("expires");
    if (expire != cookies.end()) {
        std::string now_date = get_http_date();
        Date cookie_expire(expire->second);
        Date now(now_date);

        if (cookie_expire.is_err()) {
            return false;
        }
        if (cookie_expire <= now) {
            // std::cout << RED << "expired -> cookie: " << expire->second << ", now: " << now_date << RESET << std::endl;
            return false;
        }
        // std::cout << RED << "not expire -> cookie: " << expire->second << ", now: " << now_date << RESET << std::endl;
    }
    return true;
}


std::string HttpResponse::get_user_name_from_cookie() {
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


std::string HttpResponse::get_expire_from_cookie() {
    Result<std::map<std::string, std::string>, ProcResult> result = this->request_.get_cookie();
    if (result.is_err()) {
        return EMPTY;
    }
    std::map<std::string, std::string> cookies = result.ok_value();

    std::map<std::string, std::string>::const_iterator expire;
    expire = cookies.find("expires");
    if (expire == cookies.end()) {
        return EMPTY;
    }
    return expire->second;
}


StatusCode HttpResponse::get_cookie_user_page() {
    // std::cout << RED << " get_cookie_user_page()" << RESET << std::endl;

    if (is_logged_in_user()) {
        // std::cout << RED << " logged_in_user" << RESET << std::endl;
        const std::string head = "<!doctype html>\n"
                                 "<html lang=\"ja\">\n"
                                 "<head>\n"
                                 "    <meta charset=\"UTF-8\">\n"
                                 "    <title>User page</title>\n"
                                 "</head>\n"
                                 "<body>\n"
                                 "<h1>🍪 User Page 🍪</h1>\n";

        const std::string welcome = "<h2>Welcome, " + get_user_name_from_cookie() + "</h2>";
        const std::string expire = "<h3>expire at: " + get_expire_from_cookie() + "</h3>";

        const std::string tail = "<br><br><br>\n"
                                 "<a href=\"" + this->dynamic_.COOKIE_LOGIN +"\">< back to login</a><br>"
                                 "<a href=\"/\">< back to index</a>"
                                 "</body>\n"
                                 "</html>\n";

        std::vector<unsigned char> body;
        body.insert(body.end(), head.begin(), head.end());
        body.insert(body.end(), welcome.begin(), welcome.end());
        body.insert(body.end(), expire.begin(), expire.end());
        body.insert(body.end(), tail.begin(), tail.end());
        this->body_buf_ = body;

        add_content_header("html");
        return StatusOk;
    } else {
        // std::cout << RED << " inactive user" << RESET << std::endl;

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
            time_t expire_at = std::time(NULL) + ConfigInitValue::kDefaultCookieTimeoutSec;
            cookies["expires"] = HttpResponse::get_http_date(expire_at);

            this->cookies_ = cookies;
            add_content_header("html");

            ReturnDirective redirect_to_userpage;
            redirect_to_userpage.return_on = true;
            redirect_to_userpage.code = Found;
            redirect_to_userpage.text = this->dynamic_.COOKIE_USERPAGE;
            return get_redirect_content(redirect_to_userpage);
        }
        default: {
            return MethodNotAllowed;
        }
    }
}
