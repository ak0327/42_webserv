#include "HttpMessageParser.hpp"
#include "HttpResponse.hpp"

std::map<std::string, std::vector<std::string> > get_post_parameters(const std::vector<unsigned char> &body) {
    std::map<std::string, std::vector<std::string> > parameters;

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

        key = HttpMessageParser::decode(key);
        value = HttpMessageParser::decode(value);
        parameters[key].push_back(value);
        std::cout << "key: " << key << ", value: " << value << std::endl;
    }
    return parameters;
}

// request body -> get parameters -> html
StatusCode HttpResponse::post_target() {
    std::string head = "<!doctype html>\n"
                       "<html lang=\"ja\">\n"
                       "<head>\n"
                       "    <meta charset=\"UTF-8\">\n"
                       "    <title>POST params</title>\n"
                       "</head>\n"
                       "<body>";

    std::string tail = "</body>\n"
                       "</html>";

    std::map<std::string, std::vector<std::string> > parameters = get_post_parameters(this->body_buf_);
    std::string parameters_str;

    std::map<std::string, std::vector<std::string> >::const_iterator itr;
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
