#pragma once

# include <string>
# include <vector>
# include "ConfigStruct.hpp"

struct Dynamic {
    const std::string FORM_DATA;
    const std::string RESPONSE_BODY;
    const std::string NOW;
    const std::string COOKIE_LOGIN;
    const std::string COOKIE_USERPAGE;
    const std::string SESSION_LOGIN;
    const std::string SESSION_USERPAGE;

    const time_t kSessionTimeoutSec;
    const time_t kCookieTimeoutSec;

    std::vector<std::string> DYNAMIC_PAGES;

    Dynamic()
    : FORM_DATA("/dynamic/form-data"),
      RESPONSE_BODY("/dynamic/show-response-body"),
      NOW("/dynamic/now"),
      COOKIE_LOGIN("/dynamic/cookie-login"),
      COOKIE_USERPAGE("/dynamic/cookie-user-page"),
      SESSION_LOGIN("/dynamic/session-login"),
      SESSION_USERPAGE("/dynamic/session-user-page"),
      kSessionTimeoutSec(ConfigInitValue::kDefaultSessionTimeoutSec),
      kCookieTimeoutSec(ConfigInitValue::kDefaultCookieTimeoutSec) {
        DYNAMIC_PAGES.push_back(FORM_DATA);
        DYNAMIC_PAGES.push_back(RESPONSE_BODY);
        DYNAMIC_PAGES.push_back(NOW);
        DYNAMIC_PAGES.push_back(COOKIE_LOGIN);
        DYNAMIC_PAGES.push_back(COOKIE_USERPAGE);
        DYNAMIC_PAGES.push_back(SESSION_LOGIN);
        DYNAMIC_PAGES.push_back(SESSION_USERPAGE);
    }
};
