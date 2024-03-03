#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"


namespace {

const char API_FORM_DATA[]      = "/api/form-data";
const char API_RESPONSE_BODY[]  = "/api/show-response-body";
const char API_NOW[]            = "/api/now";
const char API_LOGIN[]          = "/api/cookie-login";
const char API_USERPAGE[]       = "/api/cookie-userpage";


std::vector<std::string> init_endpoints() {
    std::vector<std::string> endpoints;
    // endpoints.push_back("");

    endpoints.push_back(API_FORM_DATA);
    endpoints.push_back(API_RESPONSE_BODY);
    endpoints.push_back(API_NOW);
    endpoints.push_back(API_LOGIN);
    endpoints.push_back(API_USERPAGE);
    return endpoints;
}

const std::vector<std::string> API_ENDPOINTS = init_endpoints();


}  // namespace


////////////////////////////////////////////////////////////////////////////////


bool HttpResponse::is_api_endpoint() {
    std::vector<std::string>::const_iterator itr;
    itr = std::find(API_ENDPOINTS.begin(), API_ENDPOINTS.end(), this->request_.request_target());
    return itr != API_ENDPOINTS.end();
}


StatusCode HttpResponse::response_api() {
    if (this->request_.request_target() == std::string(API_FORM_DATA)) {
        return show_form_data();
    }
    if (this->request_.request_target() == std::string(API_RESPONSE_BODY)) {
        return show_request_body();
    }
    if (this->request_.request_target() == std::string(API_NOW)) {
        return get_now();
    }
    if (this->request_.request_target() == std::string(API_LOGIN)) {
        return get_cookie_login_page();
    }
    if (this->request_.request_target() == std::string(API_USERPAGE)) {
        return get_cookie_user_page();
    }
    return NotFound;
}


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


StatusCode HttpResponse::get_now() {
    const std::string head = "<!doctype html>\n"
                             "<html lang=\"ja\">\n"
                             "<head>\n"
                             "    <meta charset=\"UTF-8\">\n"
                             "    <title>now</title>\n"
                             "</head>\n"
                             "<body>\n";

    const std::string now = "Now: " + get_http_date();

    const std::string tail = "</body>\n"
                             "</html>\n";

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), now.begin(), now.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    add_content_header("html");
    return StatusOk;
}


StatusCode HttpResponse::show_request_body() {
    std::string head = "<!doctype html>\n"
                       "<html lang=\"ja\">\n"
                       "<head>\n"
                       "    <meta charset=\"UTF-8\">\n"
                       "    <title>POST params</title>\n"
                       "</head>\n"
                       "<body>\n";

    std::string tail = "</body>\n"
                       "</html>\n";

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), this->body_buf_.begin(), this->body_buf_.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    add_content_header("html");
    return StatusOk;
}


StatusCode HttpResponse::show_form_data() {
    if (is_urlencoded_form_data()) {
        // DEBUG_PRINT(YELLOW, "   show_form_data -> urlencoded_form");
        return get_urlencoded_form_content();
    }
    // DEBUG_PRINT(YELLOW, "   show_form_data err: 400");
    return BadRequest;
}


// media-type = type "/" subtype parameters
// Content-Type: application/x-www-form-urlencoded
bool HttpResponse::is_urlencoded_form_data() {
    Result<MediaType, ProcResult> result = this->request_.get_content_type();
    if (result.is_err()) {
        return false;
    }
    MediaType media_type = result.ok_value();
    return media_type.type() == "application" && media_type.subtype() == "x-www-form-urlencoded";
}


UrlEncodedFormData HttpResponse::parse_urlencoded_form_data(const std::vector<unsigned char> &request_body) {
    UrlEncodedFormData parameters;

    std::vector<unsigned char> body = request_body;
    for (std::vector<unsigned char>::iterator itr = body.begin(); itr != body.end(); ++itr) {
        if (*itr == '+') {
            *itr = ' ';
        }
    }

    std::vector<std::string> name_value_pairs;
    std::vector<unsigned char>::const_iterator head, tail;
    head = body.begin();
    while (head != body.end()) {
        tail = head;
        while (tail != body.end() && *tail != '&') {
            ++tail;
        }
        std::string name_value(head, tail);
        name_value_pairs.push_back(name_value);

        head = tail;
        if (head == body.end()) {
            break;
        }
        ++head;
    }

    std::vector<std::string>::const_iterator itr;
    for (itr = name_value_pairs.begin(); itr != name_value_pairs.end(); ++itr) {
        const std::string &name_value = *itr;
        std::size_t delimiter_pos = name_value.find('=');
        if (delimiter_pos == std::string::npos) {
            continue;
        }
        std::string key = name_value.substr(0, delimiter_pos);
        std::string value = name_value.substr(delimiter_pos + 1);

        key = StringHandler::decode(key);
        value = StringHandler::decode(value);
        parameters[key].push_back(value);
        std::cout << "key: " << key << ", value: " << value << std::endl;
    }
    return parameters;
}


StatusCode HttpResponse::get_urlencoded_form_content() {
    std::string head = "<!doctype html>\n"
                       "<html lang=\"ja\">\n"
                       "<head>\n"
                       "    <meta charset=\"UTF-8\">\n"
                       "    <title>POST params</title>\n"
                       "</head>\n"
                       "<body>\n";

    std::string tail = "</body>\n"
                       "</html>\n";

    UrlEncodedFormData parameters = parse_urlencoded_form_data(this->body_buf_);
    std::string parameters_html;

    UrlEncodedFormData::const_iterator itr;
    for (itr = parameters.begin(); itr != parameters.end(); ++itr) {
        std::ostringstream oss;
        oss << itr->first << " : ";

        std::vector<std::string> params = itr->second;
        std::vector<std::string>::const_iterator param;
        for (param = params.begin(); param != params.end(); ++param) {
            oss << *param;

            if (param + 1 != params.end()) {
                oss << ", ";
            }
        }
        std::string escaped_html = HttpMessageParser::escape_html(oss.str());
        parameters_html.append(escaped_html);
        parameters_html.append("<br><br>");
    }

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), parameters_html.begin(), parameters_html.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    add_content_header("html");
    return StatusOk;
}
