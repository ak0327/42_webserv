#include <algorithm>
#include <string>
#include <vector>
#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"


bool HttpResponse::is_api_endpoint() {
    std::vector<std::string>::const_iterator itr;
    itr = std::find(API_ENDPOINTS.begin(), API_ENDPOINTS.end(), this->request_.request_target());
    return itr != API_ENDPOINTS.end();
}


StatusCode HttpResponse::response_api() {
    if (this->request_.request_target() == "/api/form-data") {
        return show_data();
    }
    if (this->request_.request_target() == "/api/show-body") {
        return show_body();
    }
    // if (this->request_.request_target() == "/api/upload") {
    //     return upload_file();
    // }
    if (this->request_.request_target() == "/api/now") {
        return get_now();
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


StatusCode HttpResponse::show_body() {
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


StatusCode HttpResponse::show_data() {
    if (is_urlencoded_form_data()) {
        // DEBUG_PRINT(YELLOW, "   show_data -> urlencoded_form");
        return get_urlencoded_form_content();
    }
    // DEBUG_PRINT(YELLOW, "   show_data err: 400");
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

    std::vector<std::string> name_value_pairs;
    std::vector<unsigned char>::const_iterator head, tail;
    head = request_body.begin();
    while (head != request_body.end()) {
        tail = head;
        while (tail != request_body.end() && *tail != '&') {
            ++tail;
        }
        std::string name_value(head, tail);
        name_value_pairs.push_back(name_value);

        head = tail;
        if (head == request_body.end()) {
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
