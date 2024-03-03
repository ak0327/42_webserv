#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "HttpResponse.hpp"
#include "StringHandler.hpp"


bool HttpResponse::is_session_active_user() {
    return true;
}


StatusCode HttpResponse::get_session_user_page() {
    if (is_session_active_user()) {
        // todo
        return StatusOk;
    } else {
        ReturnDirective redirect_to_login;
        redirect_to_login.return_on = true;
        redirect_to_login.code = Found;
        redirect_to_login.text = "/login_cookie.html";
        return get_redirect_content(redirect_to_login);
    }
}


StatusCode HttpResponse::get_session_login_page() {
    switch (this->request_.method()) {
        case kGET: {
            return get_session_user_page();
        }
        case kPOST: {
            UrlEncodedFormData parameters = parse_urlencoded_form_data(this->body_buf_);

            std::map<std::string, std::string> items;
            for (UrlEncodedFormData::const_iterator itr = parameters.begin(); itr != parameters.end(); ++itr) {
                if (itr->first == "username") {
                    items["username"] = *itr->second.begin();
                }
                if (itr->first == "email") {
                    items["email"] = *itr->second.begin();
                }
            }


            // todo: server.session <- items

            add_content_header("html");

            ReturnDirective redirect_to_userpage;
            redirect_to_userpage.return_on = true;
            redirect_to_userpage.code = Found;
            redirect_to_userpage.text = "/api/session-userpage";
            return get_redirect_content(redirect_to_userpage);
        }
        default: {
            return MethodNotAllowed;
        }
    }
}
