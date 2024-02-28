#!/bin/bash

source test/integration/test_func.sh

################################################################################

CONF_PATH="test/integration/integration_test.conf"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

test_cnt=0

ng_cnt=0
ng_cases=()

skip_cnt=0
skip_cases=()

################################################################################

./webserv $CONF_PATH &

SERVER_PID=$!

sleep 1

################################################################################

# 200 OK
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /// HTTP/1.1\r\nHost: localhost\r\n\r\n"         | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /.//../../ HTTP/1.1\r\nHost: localhost\r\n\r\n"  | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost:  localhost   \r\n\r\n"       | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /%2E%2E/ HTTP/1.1\r\nHost: localhost\r\n\r\n"    | nc localhost 4242)"   "200 OK"    "html/index.html"

expect_eq_get "$(curl -is "localhost:4242/hello.py")"   "200 OK"    "html/hello.py"
expect_eq_get "$(curl -is "localhost:4242/index.css")"  "200 OK"    "html/index.css"
expect_eq_get "$(curl -is "localhost:4242/404.html")"   "200 OK"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/50x.html")"   "200 OK"    "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/new.html")"   "200 OK"    "html/new.html"

#expect_eq_get "$(curl -is "localhost:4242/images/image1.jpg")"   "200 OK"   "html/images/image1.jpg"  // diff ng
expect_eq_get "$(curl -is "localhost:4242/a/b/c/")"              "200 OK"   "html/a/b/c/file_c.html"


# redirect -> todo: location
expect_eq_get "$(curl -is "localhost:4242/old.html")""  "   "301 Moved Permanently"    ""
# expect_eq_get "$(curl -is "localhost:4242st"  "4242"  "/autoindex_files"   "301 Moved Permanently"  ""
# expect_eq_get "$(curl -is "localhost:4242st"  "4242"  "/upload"            "301 Moved Permanently"  ""

# CGI
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py")"               "200 OK"   "html/cgi-bin/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py?query")"         "200 OK"   "html/cgi-bin/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py/path/info")"     "200 OK"   "html/cgi-bin/cgi-result/hello.txt"
# expect_eq_get "$(curl -is "localhost:4242i-bin/page.php")"""              "200 OK"   "html/cgi-bin/cgi-result/page.txt"
# expect_eq_get "$(curl -is "localhost:4242i-bin/post_simple.py")"""        "200 OK"   "html/cgi-bin/cgi-result/post_simple_get.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.sh")"               "200 OK"   "html/cgi-bin/cgi-result/hello.txt"

expect_eq_get "$(echo -en "GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n"       | nc localhost 4242)"   "400 Bad Request"    ""
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_400.py")"           "400 Bad Request"            ""
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_no_shebang.py")"    "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_wrong_shebang.py")" "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_404.py")"           "404 Not Found"              "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_500.py")"           "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_loop.py")"       "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_print.py")"      "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep5sec.py")"           "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep10sec.py")"          "500 Internal Server Error"  "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/nothing.py")"             "404 Not Found"              "html/404.html"


# 404 Not Found
expect_eq_get "$(echo -en "GET /nothing HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                  "404 Not Found"    "html/404.html"
expect_eq_get "$(echo -en "GET /nothing/ HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                 "404 Not Found"    "html/404.html"
expect_eq_get "$(echo -en "GET /nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"             "404 Not Found"    "html/404.html"
expect_eq_get "$(echo -en "GET /nothing/nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"     "404 Not Found"    "html/404.html"
expect_eq_get "$(echo -en "GET /a/b HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                      "404 Not Found"    "html/404.html"
expect_eq_get "$(echo -en "GET /a/b/c/nothing HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"            "404 Not Found"    "html/404.html"


# 405 Method Not Allowed
expect_eq_get "$(echo -en "GET /hoge/ HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                    "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /hoge/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"          "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /hoge/nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"        "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /hoge/nothing HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"             "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /hoge/huga/ HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"               "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /hoge/huga/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"     "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /show_body HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                "405 Method Not Allowed"    ""
expect_eq_get "$(echo -en "GET /show_body/ HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"               "405 Method Not Allowed"    ""


# 400 BadRequest
## invalid request line
expect_eq_get "$(echo -en "GET\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET /\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                  "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"           "400 Bad Request"    ""
expect_eq_get "$(echo -en "  GET / \r\nHost: localhost\r\n\r\n" | nc localhost 4242)"               "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"       "400 Bad Request"    ""

## invalid method
expect_eq_get "$(echo -en "get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "Get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "PUT / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "hoge / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"    ""
expect_eq_get "$(echo -en " / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"            "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"     "400 Bad Request"    ""

## invalid request target
expect_eq_get "$(echo -en "GET . HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET .. HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"      "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET ../html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"   "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET ./html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET %2E HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"       "400 Bad Request"  ""

##  invalid http-version
expect_eq_get "$(echo -en "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/120\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"          "400 Bad Request"    ""

## invalid herader
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\n\r\n" | nc localhost 4242)"                            "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\n\r\n\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost:\r\n\r\n" | nc localhost 4242)"                   "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost : localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"   ""


################################################################################

kill $SERVER_PID

################################################################################

echo
echo "================================================================"
echo " *** RESULT ***"
if [ $ng_cnt -eq 0 ] && [ $skip_cnt -eq 0 ]; then
    echo -e " ${GREEN}All tests passed successfully${RESET}"
fi

echo "  Total Tests  : $test_cnt"

echo "  Failed Tests : $ng_cnt"
if [ $ng_cnt -gt 0 ]; then
    for case in "${ng_cases[@]}"; do
        echo -e "${RED}     $case${RESET}"
    done
fi

echo "  Skipped Tests: $skip_cnt"
if [ $skip_cnt -gt 0 ]; then
    for case in "${skip_cases[@]}"; do
        echo -e "${YELLOW}     $case${RESET}"
    done
fi

echo "================================================================"

################################################################################
