#!/bin/bash

source test/integration/test_func.sh
source test/integration/prepare_test_file.sh

################################################################################

CONF_PATH="test/integration/integration_test.conf"

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

SUCCESS=0
FAILURE=1

TRUE=1
FALSE=0

test_cnt=0

ng_cnt=0
ng_cases=()

skip_cnt=0
skip_cases=()

################################################################################
echo "================================================================"
echo " GET TEST"
echo "================================================================"

pkill webserv

prepare_test_file

./webserv $CONF_PATH &


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

#expect_eq_get "$(curl -is "localhost:4242/images/image1.jpg")"   "200 OK"   "html/images/image1.jpg"  // diff?
expect_eq_get "$(curl -is "localhost:4242/a/b/c/")"              "200 OK"   "html/a/b/c/file_c.html"


# redirect -> todo: location
expect_eq_get "$(curl -is "localhost:4242/old.html")"           "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/old/")"               "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/autoindex_files")"    "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/upload")"             "301 Moved Permanently"    ""

# CGI
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py")"                         "200 OK"   "test/integration/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py?query")"                   "200 OK"   "test/integration/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py/path/info")"               "200 OK"   "test/integration/cgi-result/hello.txt"
# path... #expect_eq_get "$(curl -is "localhost:4242/cgi-bin/page.php")"               "200 OK"   "test/integration/cgi-result/page.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/post_simple.py")"                   "200 OK"   "test/integration/cgi-result/post_simple_get.txt"
expect_eq_get "$(curl -is --data "test text" localhost:4242/cgi-bin/post_simple.py)"  "200 OK"   "test/integration/cgi-result/post_simple_small.txt"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.sh")"                         "200 OK"   "test/integration/cgi-result/hello.txt"


expect_eq_get "$(echo -en "GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n"       | nc localhost 4242)"       "400 Bad Request"    ""
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_400.py")"           "400 Bad Request"             ""
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_no_shebang.py")"    "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_wrong_shebang.py")" "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/exit1.py")"               "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_404.py")"           "404 Not Found"               "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_500.py")"           "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_loop.py")"       "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_print.py")"      "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep5sec.py")"           "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep10sec.py")"          "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/nothing.py")"             "404 Not Found"               "html/404.html"


# 404 Not Found
expect_eq_get "$(curl -is "localhost:4242/nothing")"                    "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/")"                   "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing.html")"               "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/nothing.html")"       "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/a/b/c/nothing/")"             "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing")"                    "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/hoge/huga")"          "404 Not Found"    "html/404.html"


# 405 Method Not Allowed
expect_eq_get "$(curl -is "localhost:4242/delete_only/")"                 "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/index.html")"       "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/dir/")"             "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/dir/index.html")"   "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/nothing.html")"     "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/nothing.html")"     "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/api/show-response")"            "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/api/form-data")"                "405 Method Not Allowed"    ""


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


# permission
expect_eq_get "$(curl -is "localhost:4242/permission/___.html")"        "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/__x.html")"        "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_.html")"        "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__.html")"        "200 OK"              "html/permission/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/rwx.html")"        "200 OK"              "html/permission/rwx.html"

expect_eq_get "$(curl -is "localhost:4242/permission/___/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/rwx.html")"    "403 Forbidden"       ""

expect_eq_get "$(curl -is "localhost:4242/permission/__x/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/__x/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/__x/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/__x/r__.html")"    "200 OK"              "html/permission/__x/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/__x/rwx.html")"    "200 OK"              "html/permission/__x/rwx.html"

expect_eq_get "$(curl -is "localhost:4242/permission/_w_/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/rwx.html")"    "403 Forbidden"       ""

expect_eq_get "$(curl -is "localhost:4242/permission/r__/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/rwx.html")"    "403 Forbidden"       ""

expect_eq_get "$(curl -is "localhost:4242/permission/rwx/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/r__.html")"    "200 OK"              "html/permission/rwx/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/rwx.html")"    "200 OK"              "html/permission/rwx/rwx.html"



################################################################################

process_count=$(ps aux | grep '[w]ebserv' | wc -l)
if [ "$process_count" -eq 0 ]; then
  process_abort=$TRUE
else
  process_abort=$FALSE
  pkill webserv
fi

################################################################################

echo
echo "================================================================"
echo " *** GET RESULT ***"
exit_status=$FAILURE

if [ $ng_cnt -eq 0 ] && [ $skip_cnt -eq 0 ]; then
    echo -e " ${GREEN}All tests passed successfully${RESET}"
    exit_status=$SUCCESS
fi

echo "  Total Tests    : $test_cnt"

echo "  Failed Tests   : $ng_cnt"
if [ $ng_cnt -gt 0 ]; then
    for case in "${ng_cases[@]}"; do
        echo -n "     "
        echo -e "${RED}$case${RESET}"
    done
fi

echo "  Skipped Tests  : $skip_cnt"
if [ $skip_cnt -gt 0 ]; then
    for case in "${skip_cases[@]}"; do
        echo -n "     "
        echo -e "${YELLOW}$case${RESET}"
    done
fi


echo -n "  Process Aborted: "
if [ $process_abort -eq $FALSE ]; then
    echo -e "-"
else
    echo -e "${RED}Aborted${RESET}"
    exit_status=$FAILURE
fi



echo "================================================================"
echo ""

clear_test_file

exit $exit_status

################################################################################
