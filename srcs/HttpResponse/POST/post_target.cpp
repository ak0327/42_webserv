#include <algorithm>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"
#include "MediaType.hpp"

UrlEncodedFormData parse_urlencoded_form_data(const std::vector<unsigned char> &request_body) {
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

        key = HttpMessageParser::decode(key);
        value = HttpMessageParser::decode(value);
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
                       "</html>";

    UrlEncodedFormData parameters = parse_urlencoded_form_data(this->body_buf_);
    std::string parameters_str;

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
        oss << "<br><br>" << std::endl;
        parameters_str.append(oss.str());
    }

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), parameters_str.begin(), parameters_str.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    return StatusOk;
}


Result<FormData, int> parse_multipart_form_data() {
    FormData form_data;
    std::string boundary;

    // todo
    return Result<FormData, int>::ok(form_data);
}


StatusCode upload_file() {
    Result<FormData, int> parse_result = parse_multipart_form_data();
    if (parse_result.is_err()) {
        return BadRequest;
    }
    FormData form_data = parse_result.get_ok_value();

    const std::string file_name = form_data.file_name;
    const std::string path = "./html/upload/" + file_name;

    FileHandler file(path);
    return file.create_file(form_data.binary);
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
                       "</html>";

    std::vector<unsigned char> body;
    body.insert(body.end(), head.begin(), head.end());
    body.insert(body.end(), this->body_buf_.begin(), this->body_buf_.end());
    body.insert(body.end(), tail.begin(), tail.end());
    this->body_buf_ = body;

    return StatusOk;
}


// media-type = type "/" subtype parameters
// Content-Type: application/x-www-form-urlencoded
bool HttpResponse::is_urlencoded_form_data() {
    Result<MediaType, ProcResult> result = this->request_.get_content_type();
    if (result.is_err()) {
        return false;
    }
    MediaType media_type = result.get_ok_value();
    return media_type.type() == "application" && media_type.subtype() == "x-www-form-urlencoded";
}


// Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOzc5oS6JxLwBcmay
bool HttpResponse::is_multipart_form_data() {
    Result<MediaType, ProcResult> result = this->request_.get_content_type();
    if (result.is_err()) {
        return false;
    }
    MediaType media_type = result.get_ok_value();
    if (!(media_type.type() == "multipart" && media_type.subtype() == "form-data")) {
        return false;
    }

    const std::map<std::string, std::string> &parameters = media_type.parameters();
    std::map<std::string, std::string>::const_iterator itr = parameters.find("boundary");
    return itr != parameters.end() && !itr->second.empty();
}


StatusCode HttpResponse::post_target() {
    if (this->request_.request_target() == "/show_body") {
        return show_body();
    }

    if (is_urlencoded_form_data()) {
        return get_urlencoded_form_content();
    }
    if (is_multipart_form_data()) {
        return upload_file();
    }
    return BadRequest;
}
