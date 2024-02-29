#include <algorithm>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "FileHandler.hpp"
#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"
#include "HttpRequest.hpp"
#include "StringHandler.hpp"
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
                       "</html>";

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

    return StatusOk;
}


std::vector<unsigned char>::iterator get_non_const_itr(std::vector<unsigned char>::iterator begin,
                                                       std::vector<unsigned char>::const_iterator const_itr) {
    typedef std::vector<unsigned char>::const_iterator c_itr;
    std::ptrdiff_t offset = std::distance(static_cast<c_itr>(begin), const_itr);
    std::vector<unsigned char>::iterator non_const_itr = begin + offset;
    return non_const_itr;
}


// The Content-Disposition header field MUST also contain an additional parameter of "name".
Result<std::string, ProcResult> parse_file_name(const std::string &value) {
    // std::cout << RED << "    parser_file_name: 1" << RESET << std::endl;
    std::string type;
    std::map<std::string, std::string> params;
    Result<int, int> content_disposition_result;
    content_disposition_result = HttpRequest::parse_and_validate_content_disposition(value,
                                                                                     &type,
                                                                                     &params);
    if (content_disposition_result.is_err()) {
        // std::cout << RED << "    parser_file_name: 2" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    if (type != "form-data") {
        // std::cout << RED << "    parser_file_name: 3" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::map<std::string, std::string>::const_iterator itr = params.find("name");
    if (itr == params.end() || itr->second != "\"file_name\"") {
        // std::cout << RED << "    parser_file_name: 4" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }

    itr = params.find("filename");
    if (itr == params.end()) {
        // std::cout << RED << "    parser_file_name: 5" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string file_name = itr->second;
    // std::cout << RED << "    parser_file_name: 6" << RESET << std::endl;
    return Result<std::string, ProcResult>::ok(file_name);
}


Result<std::string, ProcResult> parse_content_type(const std::string &value) {
    // std::cout << RED << "    parser_content_type: 1" << RESET << std::endl;
    MediaType media_type(value);
    if (media_type.is_err()) {
        // std::cout << RED << "    parser_content_type: 2" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string content_type = media_type.type();
    if (!media_type.subtype().empty()) {
        content_type.append("/");
        content_type.append(media_type.subtype());
        // std::cout << RED << "    parser_content_type: 3" << RESET << std::endl;
    }
    // std::cout << RED << "    parser_content_type: 4" << RESET << std::endl;
    return Result<std::string, ProcResult>::ok(content_type);
}


// 4.8. Other "Content-" Header Fields
// The multipart/form-data media type does not support any MIME header fields in parts other
// than Content-Type, Content-Disposition, and (in limited circumstances) Content-Transfer-Encoding.
// Other header fields MUST NOT be included and MUST be ignored.
// https://tex2e.github.io/rfc-translater/html/rfc7578.html#4-8--Other-Content--Header-Fields
ProcResult HttpResponse::parse_until_binary(const std::string &boundary,
                                            std::string *file_name,
                                            std::string *content_type) {
    if (!file_name || !content_type) {
        return FatalError;
    }
    const std::string separator = "--" + boundary;

    Result<std::string, ProcResult> line_result;
    Result<ProcResult, StatusCode> split_result;
    while (true) {
        // std::cout << RED << "   parser1: 1" << RESET << std::endl;
        line_result = HttpRequest::pop_line_from_buf(&this->body_buf_);
        if (line_result.is_err()) {
            // std::cout << RED << "   parser1: 2c" << RESET << std::endl;
            return Failure;
        }
        std::string line = line_result.get_ok_value();
        // std::cout << RED << "   parser1: 3 line:" << line << RESET << std::endl;

        if (line == separator || line.empty()) {
            continue;
        }
        std::string name, value;
        split_result = HttpRequest::split_field_line(line, &name, &value);
        if (split_result.is_err()) {
            // std::cout << RED << "   parser1: 4                std::cout << RED << \"   parser1: 7\" << RESET << std::endl;" << RESET << std::endl;
            return Failure;
        }
        // std::cout << RED << "   parser1: 5" << RESET << std::endl;
        name = StringHandler::to_lower(name);
        DEBUG_PRINT(RED, "name[%s], value[%s]", name.c_str(), value.c_str());

        if (name == std::string(CONTENT_DISPOSITION)) {
            // std::cout << RED << "   parser1: 6" << RESET << std::endl;
            Result<std::string, ProcResult> file_name_result = parse_file_name(value);
            if (file_name_result.is_err()) {
                // std::cout << RED << "   parser1: 7 err" << RESET << std::endl;
                return Failure;
            }
            *file_name = file_name_result.get_ok_value();
            DEBUG_PRINT(RED, " file_name[%s]", file_name->c_str());

        } else if (name == std::string(CONTENT_TYPE)) {
            // std::cout << RED << "   parser1: 8" << RESET << std::endl;
            Result<std::string, ProcResult> content_type_result = parse_content_type(value);
            if (content_type_result.is_err()) {
                // std::cout << RED << "   parser1: 9 err" << RESET << std::endl;
                return Failure;
            }
            *content_type = content_type_result.get_ok_value();
            DEBUG_PRINT(RED, " content_type[%s]", content_type->c_str());

            // std::cout << RED << "   parser1: 10" << RESET << std::endl;
            break;
        }
    }

    // std::cout << RED << "   parser1: 11" << RESET << std::endl;
    line_result = HttpRequest::pop_line_from_buf(&this->body_buf_);
    if (line_result.is_err()) {
        // std::cout << RED << "   parser1: 12 err" << RESET << std::endl;
        return Failure;
    }
    std::string line = line_result.get_ok_value();
    if (!line.empty()) {
        // std::cout << RED << "   parser1: 13 err" << RESET << std::endl;
        return Failure;
    }

    // std::cout << RED << "   parser1: 14" << RESET << std::endl;
    return Success;
}


ProcResult HttpResponse::parse_binary_data(const std::string &boundary,
                                           std::vector<unsigned char> *data) {
    if (!data) {
        return FatalError;
    }

    // std::cout << RED << "   parser2: 1" << RESET << std::endl;
    std::vector<unsigned char>::const_iterator pos, next;
    pos = this->body_buf_.begin();
    while (pos != this->body_buf_.end()) {
        // std::cout << RED << "   parser2: 2" << RESET << std::endl;
        Result<std::string, ProcResult> line_result = HttpRequest::get_line(this->body_buf_, pos, &next);
        if (line_result.is_err()) {
            // std::cout << RED << "   parser2: 3" << RESET << std::endl;
            return Failure;
        }
        std::string line = line_result.get_ok_value();
        if (line == "--" + boundary + "--" || line == "--" + boundary) {
            // std::cout << RED << "   parser2: 4" << RESET << std::endl;
            if (pos != data->begin()) { --pos; }
            if (pos != data->begin()) { --pos; }
            break;
        }
        pos = next;
    }

    std::vector<unsigned char>::iterator non_const_pos = get_non_const_itr(this->body_buf_.begin(), pos);
    data->assign(this->body_buf_.begin(), non_const_pos);
    std::string debug_str(data->begin(), data->end());
    DEBUG_PRINT(RED, " binary[%s]", debug_str.c_str());
    return Success;
}


Result<FormData, ProcResult> HttpResponse::parse_multipart_form_data(const std::string &boundary) {
    // std::cout << RED << "  parser 1" << RESET << std::endl;

    if (this->body_buf_.empty() || boundary.empty()) {
        // std::cout << RED << "  parser 2" << RESET << std::endl;
        return Result<FormData, ProcResult>::err(Failure);
    }
    FormData form_data;

    // std::cout << RED << "  parser 3" << RESET << std::endl;

    parse_until_binary(boundary, &form_data.file_name, &form_data.content_type);
    parse_binary_data(boundary, &form_data.binary);

    if (HttpMessageParser::is_quoted_string(form_data.file_name)) {
        DEBUG_PRINT(RED, " quoted file_name[%s]", form_data.file_name.c_str());
        form_data.file_name = StringHandler::unquote(form_data.file_name);
        DEBUG_PRINT(RED, " unquote file_name[%s]", form_data.file_name.c_str());
    }
    if (form_data.file_name.empty() || form_data.content_type.empty()) {
        return Result<FormData, ProcResult>::err(Failure);
    }

    this->body_buf_.clear();
    return Result<FormData, ProcResult>::ok(form_data);
}


StatusCode HttpResponse::upload_file(const std::string &boundary) {
    // std::cout << RED << " upload 1" << RESET << std::endl;
    Result<FormData, ProcResult> parse_result = parse_multipart_form_data(boundary);
    if (parse_result.is_err()) {
        // std::cout << RED << " upload 2" << RESET << std::endl;
        return BadRequest;
    }
    // std::cout << RED << " upload 3" << RESET << std::endl;
    FormData form_data = parse_result.get_ok_value();

    const std::string file_name = form_data.file_name;
    const std::string path = "./html/upload/" + file_name;

    FileHandler file(path);
    // std::cout << RED << " upload 4 path:" << path << RESET << std::endl;
    StatusCode upload_result = file.create_file(form_data.binary);

    if (upload_result == StatusOk) {
        // upload_result = SeeOther;
        upload_result = Created;
        this->headers_["Location"] = "/upload/";

        std::string jump_to_upload = "<!doctype html>\n"
                                     "<html lang=\"ja\">\n"
                                     "<head>\n"
                                     "    <meta charset=\"UTF-8\">\n"
                                     "    <title>POST params</title>\n"
                                     "</head>\n"
                                     "<body>\n"
                                     "<a href=\"/upload/\">jump to upload</a>"
                                     "</body>\n"
                                     "</html>";
        this->body_buf_.assign(jump_to_upload.begin(), jump_to_upload.end());
    }
    return upload_result;
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
bool HttpResponse::is_multipart_form_data(std::string *boundary) {
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
    if (itr == parameters.end()) {
        return false;
    }
    if (itr->second.empty()) {
        return false;
    }
    if (boundary) {
        *boundary = itr->second;
    }
    return true;
}


// static
//   file      -> error
//   directory -> error
// dynamic
//   cgi       -> error / response
//   api       -> error / response
StatusCode HttpResponse::post_target() {
    // std::cout << RED << "post 1" << RESET << std::endl;
    if (this->request_.request_target() == "/show_body") {
        return show_body();
    }
    // std::cout << RED << "post 2" << RESET << std::endl;
    if (is_urlencoded_form_data()) {
        return get_urlencoded_form_content();
    }
    // std::cout << RED << "post 3" << RESET << std::endl;
    std::string boundary;
    if (is_multipart_form_data(&boundary)) {
        return upload_file(boundary);
    }
    // std::cout << RED << "post 4" << RESET << std::endl;
    return BadRequest;
}
