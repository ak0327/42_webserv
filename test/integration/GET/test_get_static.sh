#!/bin/bash

test() {
    local request=$1
    local host_and_port=$2
    local expected_start_line=$3
    local expected_file=$4

    local response_file="${TEST_DIR}response.txt"

    local call_line=${BASH_LINENO[0]}

    echo "----------------------------------------------------------------"
    ((test_cnt++))
    echo "TEST No.${test_cnt} (L${call_line})"

    if [ -n "$expected_file" ] && [ ! -f "$expected_file" ]; then
        echo -e " ${YELLOW}Test No.${test_cnt} skipped: Expected file '$expected_file' not found${RESET}"
        ((skip_cnt++))
        skip_cases+=("No.${test_cnt} (L${call_line})")
        return
    fi

    read host port <<< "${host_and_port}"
    echo -en ${request} | nc ${host} ${port} > ${response_file}

#     curl -s -i -H "Host: ${host}" "http://${host}:${port}${path}" > ${response_file}

    local actual_start_line=$(head -n 1 ${response_file} | tr -d '\r')

    echo -n " Start-Line  : "
    if [ "$expected_start_line" == "$actual_start_line" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [${request}]")
        echo -e "${RED}NG -> Expected: \"$expected_start_line\", Actual: \"$actual_start_line\"${RESET}"
    fi

    local body_start_line=$(awk '/^\r$/{print NR + 1; exit}' ${response_file})
    if [ -z "$body_start_line" ]; then
        body_start_line=$(awk '/^$/{print NR + 1; exit}' ${response_file})
    fi


    echo -n " Request-Body: "
    if [ -z "$expected_file" ]; then
        diff_output=$(diff -u <(echo -n "") <(tail -n +${body_start_line} "${response_file}"))
    else
        diff_output=$(diff -u "${expected_file}" <(tail -n +${body_start_line} "${response_file}"))
    fi

    if [ -z "$diff_output" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${RED}NG${RESET}"
        echo "${diff_output}"
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG: [${request}]")
    fi

    rm -f ${response_file}
}

################################################################################

CONF_PATH="test/integration/integration_test.conf"

TEST_DIR="test/integration/GET/"
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
## html
test "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET /// HTTP/1.1\r\nHost: localhost\r\n\r\n"          "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET /.//../../ HTTP/1.1\r\nHost: localhost\r\n\r\n"   "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET   /   HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET / HTTP/1.1\r\nHost:  localhost   \r\n\r\n"        "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"
test "GET /%2E%2E/ HTTP/1.1\r\nHost: localhost\r\n\r\n"     "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.html"

test "GET /hello.py HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 200 OK"   "html/hello.py"
test "GET /index.css HTTP/1.1\r\nHost: localhost\r\n\r\n"   "localhost 4242"  "HTTP/1.1 200 OK"   "html/index.css"
test "GET /404.html HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 200 OK"   "html/404.html"
test "GET /50x.html HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 200 OK"   "html/50x.html"
test "GET /new.html HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 200 OK"   "html/new.html"

test "GET /images/image1.jpg HTTP/1.1\r\nHost: localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 200 OK"   "html/images/image1.jpg"
test "GET /a/b/c/ HTTP/1.1\r\nHost: localhost\r\n\r\n"                  "localhost 4242"  "HTTP/1.1 200 OK"   "html/a/b/c/file_c.html"


# redirect -> todo: location
test "GET /old.html HTTP/1.1\r\nHost: localhost\r\n\r\n"                "localhost 4242"  "HTTP/1.1 301 Moved Permanently"    ""
# test "localhost"  "4242"  "/autoindex_files"   "HTTP/1.1 301 Moved Permanently"  ""
# test "localhost"  "4242"  "/upload"            "HTTP/1.1 301 Moved Permanently"  ""

# CGI
test "GET /cgi-bin/hello.py HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/hello.txt"
test "GET /cgi-bin/hello.py?query HTTP/1.1\r\nHost: localhost\r\n\r\n"      "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/hello.txt"
test "GET /cgi-bin/hello.py/path/info HTTP/1.1\r\nHost: localhost\r\n\r\n"  "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/hello.txt"
# test "GET /cgi-bin/page.php HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/page.txt"
test "GET /cgi-bin/post_simple.py HTTP/1.1\r\nHost: localhost\r\n\r\n"      "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/post_simple_get.txt"
test "GET /cgi-bin/hello.sh HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 200 OK"   "html/cgi-bin/cgi-result/hello.txt"

test "GET /cgi-bin/hello_400.py HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 400 Bad Request"            ""
test "GET /cgi-bin/error_no_shebang.py HTTP/1.1\r\nHost: localhost\r\n\r\n"     "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/error_wrong_shebang.py HTTP/1.1\r\nHost: localhost\r\n\r\n"  "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/hello_404.py HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 404 Not Found"              "html/404.html"
test "GET /cgi-bin/hello_500.py HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/infinite_loop.py HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/infinite_print.py HTTP/1.1\r\nHost: localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/sleep5sec.py HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/sleep10sec.py HTTP/1.1\r\nHost: localhost\r\n\r\n"           "localhost 4242"  "HTTP/1.1 500 Internal Server Error"  "html/50x.html"
test "GET /cgi-bin/nothing.py HTTP/1.1\r\nHost: localhost\r\n\r\n"              "localhost 4242"  "HTTP/1.1 404 Not Found"              "html/404.html"


# 404 Not Found
test "GET /nothing HTTP/1.1\r\nHost: localhost\r\n\r\n"                 "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"
test "GET /nothing/ HTTP/1.1\r\nHost: localhost\r\n\r\n"                "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"
test "GET /nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"
test "GET /nothing/nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"
test "GET /a/b HTTP/1.1\r\nHost: localhost\r\n\r\n"                     "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"
test "GET /a/b/c/nothing HTTP/1.1\r\nHost: localhost\r\n\r\n"           "localhost 4242"  "HTTP/1.1 404 Not Found"    "html/404.html"


# 405 Method Not Allowed
test "GET /hoge/ HTTP/1.1\r\nHost: localhost\r\n\r\n"                   "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /hoge/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"         "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /hoge/nothing.html HTTP/1.1\r\nHost: localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /hoge/nothing HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /hoge/huga/ HTTP/1.1\r\nHost: localhost\r\n\r\n"              "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /hoge/huga/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /show_body HTTP/1.1\r\nHost: localhost\r\n\r\n"               "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""
test "GET /show_body/ HTTP/1.1\r\nHost: localhost\r\n\r\n"              "localhost 4242"  "HTTP/1.1 405 Method Not Allowed"    ""


# 400 BadRequest
## invalid request line
test "GET\r\nHost: localhost\r\n\r\n"                   "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET\r\nHost: localhost\r\n\r\n"                   "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET /\r\nHost: localhost\r\n\r\n"                 "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET HTTP/1.1\r\nHost: localhost\r\n\r\n"          "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test " GET / HTTP/1.1 \r\nHost: localhost\r\n\r\n"      "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET / / HTTP/1.1\r\nHost: localhost\r\n\r\n"      "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""

## invalid method
test "get / HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "Get / HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "get / HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "PUT / HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "hoge / HTTP/1.1\r\nHost: localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "/ HTTP/1.1\r\nHost: localhost\r\n\r\n"            "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"    "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""

## invalid request target
test "GET . HTTP/1.1\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET .. HTTP/1.1\r\nHost: localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET html HTTP/1.1\r\nHost: localhost\r\n\r\n"     "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET ../html HTTP/1.1\r\nHost: localhost\r\n\r\n"  "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET ./html HTTP/1.1\r\nHost: localhost\r\n\r\n"   "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET %2E HTTP/1.1\r\nHost: localhost\r\n\r\n"      "localhost 4242"  "HTTP/1.1 400 Bad Request"  ""

##  invalid http-version
test "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET / HTTP/120\r\nHost: localhost\r\n\r\n"        "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""
test "GET / HTTP1.1\r\nHost: localhost\r\n\r\n"         "localhost 4242"  "HTTP/1.1 400 Bad Request"    ""

## invalid herader
test "GET / HTTP/1.1\r\n\r\n"                           "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""
test "GET / HTTP/1.1\r\n\r\n\r\n\r\n"                   "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""
test "GET / HTTP/1.1\r\nHost:\r\n\r\n"                  "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""
test "GET / HTTP/1.1\r\nHost : localhost\r\n\r\n"       "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""
test "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n"            "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""
test "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n"            "localhost 4242"  "HTTP/1.1 400 Bad Request"   ""


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
