#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "Dynamic.hpp"
#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"


bool HttpResponse::is_dynamic_endpoint() {
    std::vector<std::string>::const_iterator itr;
    itr = std::find(this->dynamic_.DYNAMIC_PAGES.begin(),
                    this->dynamic_.DYNAMIC_PAGES.end(),
                    this->request_.request_target());
    return itr != this->dynamic_.DYNAMIC_PAGES.end();
}


StatusCode HttpResponse::response_dynamic() {
    const std::string target = this->request_.request_target();
    if (target == this->dynamic_.FORM_DATA) {
        return show_form_data();
    }
    if (target == this->dynamic_.RESPONSE_BODY) {
        return show_request_body();
    }
    if (target == this->dynamic_.NOW) {
        return get_now();
    }
    if (target == this->dynamic_.COOKIE_LOGIN) {
        return get_cookie_login_page();
    }
    if (target == this->dynamic_.COOKIE_USERPAGE) {
        return get_cookie_user_page();
    }
    if (target == this->dynamic_.SESSION_LOGIN) {
        return get_session_login_page();
    }
    if (target == this->dynamic_.SESSION_USERPAGE) {
        return get_session_user_page();
    }
    return NotFound;
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
        DEBUG_PRINT(YELLOW, "parse_urlencoded: key[%s] value[%s]", key.c_str(), value.c_str());
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
