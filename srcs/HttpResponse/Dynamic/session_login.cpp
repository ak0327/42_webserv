#include <algorithm>
#include <ctime>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "Dynamic.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"
#include "StringHandler.hpp"


Result<SessionItr , bool> HttpResponse::is_session_active_user() {
    DEBUG_PRINT(MAGENTA, "is_sesison_active_user");
    Result<std::map<std::string, std::string>, ProcResult> result = this->request_.get_cookie();
    if (result.is_err()) {
        return Result<SessionItr , bool>::err(false);
    }
    std::map<std::string, std::string> cookies = result.ok_value();

    std::map<std::string, std::string>::const_iterator session_id = cookies.find(std::string(SESSION_ID));
    if (session_id == cookies.end()) {
        return Result<SessionItr , bool>::err(false);
    }

    std::string id = session_id->second;
    DEBUG_PRINT(MAGENTA, " id: [%s]", id.c_str());

    std::map<std::string, Session>::iterator itr = this->sessions_->find(id);
    if (itr == this->sessions_->end()) {
        DEBUG_PRINT(MAGENTA, " id not found");
        return Result<SessionItr , bool>::err(false);
    }
    Session session = itr->second;
    if (session.is_expired()) {
        this->sessions_->erase(itr);
        DEBUG_PRINT(MAGENTA, " expired");
        return Result<SessionItr , bool>::err(false);
    }
    DEBUG_PRINT(MAGENTA, " ok -> active");
    return Result<SessionItr , bool>::ok(itr);
}


Result<std::string, ProcResult> HttpResponse::generate_new_id() {
    std::string new_id;
    int counter = 0;

    while (counter < 5) {
        new_id = Session::generate_hash();
        if (this->sessions_->find(new_id) == this->sessions_->end()) {
            DEBUG_PRINT(MAGENTA, "generate_new_id: [%s]", new_id.c_str());
            return Result<std::string, ProcResult>::ok(new_id);
        }
        ++counter;
    }
    return Result<std::string, ProcResult>::err(Failure);
}


void HttpResponse::update_counter(const SessionItr &itr) {
    std::map<std::string, std::string> data = itr->second.data();

    std::istringstream iss(data["counter"]);
    std::size_t value;
    iss >> value;

    DEBUG_PRINT(MAGENTA, " update_counter  value: %zu", value);
    itr->second.add_data("counter", StringHandler::to_string(++value));
}


ProcResult HttpResponse::update_session_data(SessionItr *itr) {
    if (!itr) { return Failure; }

    (*itr)->second.update_expire(this->server_config_.session_timeout_sec);
    update_counter(*itr);

    std::string old_id = (*itr)->second.id();

    Result<std::string, ProcResult> id_result = generate_new_id();
    if (id_result.is_err()) {
        return Failure;
    }
    std::string new_id = id_result.ok_value();
    DEBUG_PRINT(MAGENTA, "old_id: [%s], new_id: [%s]", old_id.c_str(), new_id.c_str());

    (*itr)->second.update_id(new_id);
    (*this->sessions_)[new_id] = (*itr)->second;
    this->sessions_->erase(*itr);

    *itr = (*this->sessions_).find(new_id);
    return Success;
}


StatusCode HttpResponse::get_session_user_page() {
    DEBUG_PRINT(MAGENTA, "session_user_page 1");
    Result<SessionItr, bool> active = is_session_active_user();

    if (active.is_ok()) {
        DEBUG_PRINT(MAGENTA, "session_user_page active");
        SessionItr itr = active.ok_value();
        if (update_session_data(&itr) == Failure) {
            return InternalServerError;
        }
        Session session = itr->second;
        std::map<std::string, std::string> session_data = session.data();

        const std::string head = "<!doctype html>\n"
                                 "<html lang=\"ja\">\n"
                                 "<head>\n"
                                 "    <meta charset=\"UTF-8\">\n"
                                 "    <title>Login page</title>\n"
                                 "</head>\n"
                                 "<body>\n"
                                 "<h1>🍡 Login Page 🍡</h1>\n";

        const std::string welcome = "<h2>Welcome, " + session_data["username"] + "</h2>";
        const std::string counter = "<h3>counter: " + session_data["counter"] + "</h3>";

        const std::string expire = "<h3>expire at: " + HttpResponse::get_http_date_jst(session.expire_time()) + "</h3>";

        const std::string tail = "<br><br><br>\n"
                                 "<a href=\"/\">< back to index</a>"
                                 "</body>\n"
                                 "</html>\n";

        std::vector<unsigned char> body;
        body.insert(body.end(), head.begin(), head.end());
        body.insert(body.end(), welcome.begin(), welcome.end());
        body.insert(body.end(), counter.begin(), counter.end());
        body.insert(body.end(), expire.begin(), expire.end());
        body.insert(body.end(), tail.begin(), tail.end());
        this->body_buf_ = body;


        add_content_header("html");
        std::map<std::string, std::string> new_cookies;
        new_cookies[std::string(SESSION_ID)] = session.id();
        this->cookies_ = new_cookies;

        DEBUG_PRINT(MAGENTA, " cookie session_id:[%s]", session.id().c_str());

        return StatusOk;
    } else {
        DEBUG_PRINT(MAGENTA, "session_user_page inactive");

        ReturnDirective redirect_to_login;
        redirect_to_login.return_on = true;
        redirect_to_login.code = Found;
        redirect_to_login.text = "/login_session.html";
        return get_redirect_content(redirect_to_login);
    }
}


ProcResult HttpResponse::add_init_session_data(const std::map<std::string, std::string> &data) {
    int try_count = 0;

    while (try_count < 3) {
        Result<std::string, ProcResult> id_result = generate_new_id();
        if (id_result.is_err()) {
            return Failure;
        }
        std::string id = id_result.ok_value();

        if (this->sessions_->find(id) == this->sessions_->end()) {
            Session new_session(id, data, this->server_config_.session_timeout_sec);
            new_session.add_data("counter", "0");
            (*this->sessions_)[id] = new_session;
            DEBUG_PRINT(MAGENTA, " new_id: %s", id.c_str());

            std::map<std::string, std::string> new_cookies;
            new_cookies[std::string(SESSION_ID)] = id;
            this->cookies_ = new_cookies;

            return Success;
        }
        try_count++;  // impossible maybe...
    }
    return Failure;
}


StatusCode HttpResponse::get_session_login_page() {
    DEBUG_PRINT(MAGENTA, "get_session_login_page 1");
    switch (this->request_.method()) {
        case kGET: {
            DEBUG_PRINT(MAGENTA, "get_session_login_page 2 get");
            return get_session_user_page();
        }
        case kPOST: {
            DEBUG_PRINT(MAGENTA, "get_session_login_page 3 post");
            UrlEncodedFormData parameters = parse_urlencoded_form_data(this->body_buf_);

            DEBUG_PRINT(MAGENTA, "get_session_login_page 4");
            std::map<std::string, std::string> items;
            for (UrlEncodedFormData::const_iterator itr = parameters.begin(); itr != parameters.end(); ++itr) {
                if (itr->first == "username") {
                    items["username"] = *itr->second.begin();
                    DEBUG_PRINT(MAGENTA, " username: %s", items["username"].c_str());
                }
                if (itr->first == "email") {
                    items["email"] = *itr->second.begin();
                    DEBUG_PRINT(MAGENTA, " email: %s", items["email"].c_str());
                }
            }

            DEBUG_PRINT(MAGENTA, "get_session_login_page 5");
            ProcResult init_result = add_init_session_data(items);
            if (init_result == Failure) {
                return InternalServerError;
            }

            add_content_header("html");

            ReturnDirective redirect_to_userpage;
            redirect_to_userpage.return_on = true;
            redirect_to_userpage.code = Found;
            redirect_to_userpage.text = this->dynamic_.SESSION_USERPAGE;
            return get_redirect_content(redirect_to_userpage);
        }
        default: {
            return MethodNotAllowed;
        }
    }
}
