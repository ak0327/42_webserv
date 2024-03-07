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

std::vector<unsigned char>::iterator get_non_const_itr(std::vector<unsigned char>::iterator begin,
                                                       std::vector<unsigned char>::const_iterator const_itr) {
    typedef std::vector<unsigned char>::const_iterator c_itr;
    std::ptrdiff_t offset = std::distance(static_cast<c_itr>(begin), const_itr);
    std::vector<unsigned char>::iterator non_const_itr = begin + offset;
    return non_const_itr;
}


// The Content-Disposition header field MUST also contain an additional parameter of "name".
Result<std::string, ProcResult> parse_file_name(const std::string &value) {
    // std::cout << WHITE << "    parser_file_name: 1" << RESET << std::endl;
    std::string type;
    std::map<std::string, std::string> params;
    Result<int, int> content_disposition_result;
    content_disposition_result = HttpRequest::parse_and_validate_content_disposition(value,
                                                                                     &type,
                                                                                     &params);
    if (content_disposition_result.is_err()) {
        // std::cout << WHITE << "    parser_file_name: 2" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    if (type != "form-data") {
        // std::cout << WHITE << "    parser_file_name: 3" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::map<std::string, std::string>::const_iterator itr = params.find("name");
    if (itr == params.end() || itr->second != "\"file_name\"") {
        // std::cout << WHITE << "    parser_file_name: 4" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }

    itr = params.find("filename");
    if (itr == params.end()) {
        // std::cout << WHITE << "    parser_file_name: 5" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string file_name = itr->second;
    // std::cout << WHITE << "    parser_file_name: 6" << RESET << std::endl;
    return Result<std::string, ProcResult>::ok(file_name);
}


Result<std::string, ProcResult> parse_content_type(const std::string &value) {
    // std::cout << WHITE << "    parser_content_type: 1" << RESET << std::endl;
    MediaType media_type(value);
    if (media_type.is_err()) {
        // std::cout << WHITE << "    parser_content_type: 2" << RESET << std::endl;
        return Result<std::string, ProcResult>::err(Failure);
    }
    std::string content_type = media_type.type();
    if (!media_type.subtype().empty()) {
        content_type.append("/");
        content_type.append(media_type.subtype());
        // std::cout << WHITE << "    parser_content_type: 3" << RESET << std::endl;
    }
    // std::cout << WHITE << "    parser_content_type: 4" << RESET << std::endl;
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
        // std::cout << WHITE << "   parser1: 1" << RESET << std::endl;
        line_result = HttpRequest::pop_line_from_buf(&this->body_buf_);
        if (line_result.is_err()) {
            // std::cout << WHITE << "   parser1: 2c" << RESET << std::endl;
            return Failure;
        }
        std::string line = line_result.ok_value();
        // std::cout << WHITE << "   parser1: 3 line:" << line << RESET << std::endl;

        if (line == separator || line.empty()) {
            continue;
        }
        std::string name, value;
        split_result = HttpRequest::split_field_line(line, &name, &value);
        if (split_result.is_err()) {
            // std::cout << WHITE << "   parser1: 4                std::cout << WHITE << \"   parser1: 7\" << RESET << std::endl;" << RESET << std::endl;
            return Failure;
        }
        // std::cout << WHITE << "   parser1: 5" << RESET << std::endl;
        name = StringHandler::to_lower(name);
        DEBUG_PRINT(WHITE, "name[%s], value[%s]", name.c_str(), value.c_str());

        if (name == std::string(CONTENT_DISPOSITION)) {
            // std::cout << WHITE << "   parser1: 6" << RESET << std::endl;
            Result<std::string, ProcResult> file_name_result = parse_file_name(value);
            if (file_name_result.is_err()) {
                // std::cout << WHITE << "   parser1: 7 err" << RESET << std::endl;
                return Failure;
            }
            *file_name = file_name_result.ok_value();
            DEBUG_PRINT(WHITE, " file_name[%s]", file_name->c_str());

        } else if (name == std::string(CONTENT_TYPE)) {
            // std::cout << WHITE << "   parser1: 8" << RESET << std::endl;
            Result<std::string, ProcResult> content_type_result = parse_content_type(value);
            if (content_type_result.is_err()) {
                // std::cout << WHITE << "   parser1: 9 err" << RESET << std::endl;
                return Failure;
            }
            *content_type = content_type_result.ok_value();
            DEBUG_PRINT(WHITE, " content_type[%s]", content_type->c_str());

            // std::cout << WHITE << "   parser1: 10" << RESET << std::endl;
            break;
        }
    }

    // std::cout << WHITE << "   parser1: 11" << RESET << std::endl;
    line_result = HttpRequest::pop_line_from_buf(&this->body_buf_);
    if (line_result.is_err()) {
        // std::cout << WHITE << "   parser1: 12 err" << RESET << std::endl;
        return Failure;
    }
    std::string line = line_result.ok_value();
    if (!line.empty()) {
        // std::cout << WHITE << "   parser1: 13 err" << RESET << std::endl;
        return Failure;
    }

    // std::cout << WHITE << "   parser1: 14" << RESET << std::endl;
    return Success;
}


ProcResult HttpResponse::parse_binary_data(const std::string &boundary,
                                           std::vector<unsigned char> *data) {
    if (!data) {
        return FatalError;
    }

    // std::cout << WHITE << "   parser2: 1" << RESET << std::endl;
    std::vector<unsigned char>::const_iterator pos, next;
    pos = this->body_buf_.begin();
    while (pos != this->body_buf_.end()) {
        // std::cout << WHITE << "   parser2: 2" << RESET << std::endl;
        Result<std::string, ProcResult> line_result = HttpRequest::get_line(this->body_buf_, pos, &next);
        if (line_result.is_err()) {
            // std::cout << WHITE << "   parser2: 3" << RESET << std::endl;
            return Failure;
        }
        std::string line = line_result.ok_value();
        if (line == "--" + boundary + "--" || line == "--" + boundary) {
            // std::cout << WHITE << "   parser2: 4" << RESET << std::endl;
            if (pos != data->begin()) { --pos; }
            if (pos != data->begin()) { --pos; }
            break;
        }
        pos = next;
    }

    std::vector<unsigned char>::iterator non_const_pos = get_non_const_itr(this->body_buf_.begin(), pos);
    data->assign(this->body_buf_.begin(), non_const_pos);
    std::string debug_str(data->begin(), data->end());
    DEBUG_PRINT(WHITE, " binary[%s]", debug_str.c_str());
    return Success;
}


Result<FormData, ProcResult> HttpResponse::parse_multipart_form_data(const std::string &boundary) {
    if (this->body_buf_.empty() || boundary.empty()) {
        return Result<FormData, ProcResult>::err(Failure);
    }
    FormData form_data;
    parse_until_binary(boundary, &form_data.file_name, &form_data.content_type);
    parse_binary_data(boundary, &form_data.binary);

    if (HttpMessageParser::is_quoted_string(form_data.file_name)) {
        form_data.file_name = StringHandler::unquote(form_data.file_name);
    }
    if (form_data.file_name.empty() || form_data.content_type.empty()) {
        return Result<FormData, ProcResult>::err(Failure);
    }

    this->body_buf_.clear();
    return Result<FormData, ProcResult>::ok(form_data);
}


StatusCode HttpResponse::upload_multipart_form_data(const std::string &boundary) {
    // std::cout << WHITE << " upload 1" << RESET << std::endl;
    Result<FormData, ProcResult> parse_result = parse_multipart_form_data(boundary);
    if (parse_result.is_err()) {
        // std::cout << WHITE << " upload 2" << RESET << std::endl;
        return BadRequest;
    }
    // std::cout << WHITE << " upload 3" << RESET << std::endl;
    FormData form_data = parse_result.ok_value();

    const std::string file_name = form_data.file_name;
    std::string rooted_path = get_rooted_path();
    if (!StringHandler::has_trailing_slash(rooted_path)) {
        rooted_path.append("/");
    }
    const std::string path = rooted_path + file_name;

    FileHandler file(path);
    // std::cout << WHITE << " upload 4 path:" << path << RESET << std::endl;
    StatusCode upload_result = file.create_file(form_data.binary);

    if (upload_result == StatusOk) {
        // upload_result = SeeOther;
        upload_result = Created;
        this->headers_["Location"] = "/upload/" + form_data.file_name;

        std::string jump_to_upload = "<!doctype html>\n"
                                     "<html lang=\"ja\">\n"
                                     "<head>\n"
                                     "    <meta charset=\"UTF-8\">\n"
                                     "    <title>POST params</title>\n"
                                     "</head>\n"
                                     "<body>\n"
                                     "<a href=\"/upload/\">jump to upload</a>"
                                     "</body>\n"
                                     "</html>\n";
        this->body_buf_.assign(jump_to_upload.begin(), jump_to_upload.end());

        add_content_header("html");
    }
    return upload_result;
}


// Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOzc5oS6JxLwBcmay
bool HttpResponse::is_multipart_form_data(std::string *boundary) {
    Result<MediaType, ProcResult> result = this->request_.get_content_type();
    if (result.is_err()) {
        return false;
    }
    MediaType media_type = result.ok_value();
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


StatusCode HttpResponse::upload_file() {
    std::string boundary;
    if (is_multipart_form_data(&boundary)) {
        // DEBUG_PRINT(YELLOW, "    upload_file -> multipart_form");
        return upload_multipart_form_data(boundary);
    }
    // DEBUG_PRINT(YELLOW, "    upload_file err: 400");
    return BadRequest;
}


// static
//   file      -> error
//   directory -> error
// dynamic
//   cgi       -> error / response
//   api       -> error / response
StatusCode HttpResponse::post_target() {
    // DEBUG_PRINT(YELLOW, "  POST 1 target[%s]", this->request_.request_target().c_str());

    if (!is_method_available()) {
        // DEBUG_PRINT(YELLOW, "  POST 2 err: 405");
        return MethodNotAllowed;
    }

    // dynamic?
    //  Yes -> dynamic
    if (is_dynamic_endpoint()) {
        // DEBUG_PRINT(YELLOW, "  POST 3 -> dynamic");
        return response_dynamic();
    }

    std::string boundary;
    if (is_multipart_form_data(&boundary)) {
        // DEBUG_PRINT(YELLOW, "    upload_file -> multipart_form");
        return upload_multipart_form_data(boundary);
    }
    // DEBUG_PRINT(YELLOW, "    upload_file err: 400");

    // std::cout << WHITE << "post 4" << RESET << std::endl;
    // DEBUG_PRINT(YELLOW, "  POST 4s err: 400");
    return BadRequest;
}
