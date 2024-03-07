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

defunct_before=0
defunct_after=0
defunct_count=0
defunct_generated=$FALSE
process_abort=$FALSE

################################################################################

start_up "ERROR TEST"

################################################################################

## invalid http-version: 400
expect_eq_get "$(echo -en "GET / HTTP/4.0\r\nHost: host\r\n\r\n" | nc localhost 4242)"            "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1.9\r\nHost: host\r\n\r\n" | nc localhost 4242)"            "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1\r\nHost: host\r\n\r\n" | nc localhost 4242)"              "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1..0\r\nHost: host\r\n\r\n" | nc localhost 4242)"           "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1.1.\r\nHost: host\r\n\r\n" | nc localhost 4242)"           "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1.1.1\r\nHost: host\r\n\r\n" | nc localhost 4242)"          "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP1.1\r\nHost: host\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP9999999999999999999999999\r\nHost: host\r\n\r\n" | nc localhost 4242)"    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / http1.1\r\nHost: host\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / HTTP/1.1 HTTP/1.1\r\nHost: host\r\n\r\n" | nc localhost 4242)"   "400 Bad Request"    ""


# 411 Length Required
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nlength required" | nc localhost 4242)"                    "411 Length Required"     ""


# 413 payload too large
expect_eq_get "$(curl -isH "Content-Length: 1100000"  "localhost:4242/")"                                                     "413 Payload Too Large"    ""
large=`python3 -c "print('a'*110000)"`
expect_eq_get "$(curl -is -H "Content-Length: 1100" --data "$large" "Content-Length: 1100000"  "localhost:4242/")"            "413 Payload Too Large"    ""

expect_eq_get "$(curl -is -H "Content-Length: 21"  "localhost:4242/dir_a/")"                                                  "413 Payload Too Large"    ""
expect_eq_get "$(curl -i -X GET -H "Content-Length: 1" --data "ignored"  "localhost:4242/cgi-bin/post_simple.py")"            "413 Payload Too Large"    ""
expect_eq_get "$(curl -is -H "Content-Length: 21"  -X GET --data "$(python3 -c "print('a'*21)")"  "localhost:4242/dir_a/")"   "413 Payload Too Large"    ""
expect_eq_get "$(curl -is -X GET --data "$(python3 -c "print('a'*100)")"  "localhost:4242/dir_a/")"                           "413 Payload Too Large"    ""


# 414 URI Too Long
long_url=`python3 -c "print('a' * 1024)"`
expect_eq_get "$(curl -is "localhost:4242/$long_url")"   "414 URI Too Long"    ""

long_url=`python3 -c "print('a' * 10000)"`
expect_eq_get "$(curl -is "localhost:4242/$long_url")"   "400 Bad Request"    ""

long_url=`python3 -c "print('a' * 100000)"`
expect_eq_get "$(curl -is "localhost:4242/$long_url")"   "400 Bad Request"    ""


# 415 Unsupported Media Type
expect_eq_get "$(curl -is "localhost:4242/ng_type.ng")"                           "415 Unsupported Media Type"    ""
expect_eq_get "$(curl -is -H "Content-Type: text/xml"   "localhost:4242/new/")"   "415 Unsupported Media Type"    ""
expect_eq_get "$(curl -is -H "Content-Type: audio/mpeg" "localhost:4242/new/")"   "415 Unsupported Media Type"    ""
expect_eq_get "$(curl -is -H "Content-Type: hoge/text"  "localhost:4242/new/")"   "415 Unsupported Media Type"    ""
expect_eq_get "$(curl -is -H "Content-Type: x/y"        "localhost:4242/new/")"   "415 Unsupported Media Type"    ""

expect_eq_get "$(curl -is "localhost:4242/ng_type.nothing")"                      "404 Not Found"                 "html/404.html"


# 431 Request Header Fields Too Large
large=`python3 -c "print('a'*10000)"`
expect_eq_get "$(curl -isH "$large: hoge" "localhost:4242/")"     "431 Request Header Fields Too Large"     ""
expect_eq_get "$(curl -isH "a: $large" "localhost:4242/")"        "431 Request Header Fields Too Large"     ""
expect_eq_get "$(curl -isH "Host: $large" "localhost:4242/")"     "431 Request Header Fields Too Large"     ""
expect_eq_get "$(curl -isH "Cookie: $large" "localhost:4242/")"   "431 Request Header Fields Too Large"     ""

large_cmd=`python3 -c "print('Cookie: 012345=67890\r\n' * 5000)"`
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n$large_cmd\r\n" | nc localhost 4242)"  "431 Request Header Fields Too Large"    ""


# 501

## not supported method: 501
expect_eq_get "$(curl -is -X  HEAD "localhost:4242")"                   "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  HEAD "localhost:4242/nothing")"           "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  HEAD "localhost:4242/nothing.html")"      "501 Not Implemented"    ""

expect_eq_get "$(curl -is -X  PUT "localhost:4242")"                    "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  PUT "localhost:4242/nothing")"            "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  PUT "localhost:4242/nothing.html")"       "501 Not Implemented"    ""

expect_eq_get "$(curl -is -X  CONNECT "localhost:4242")"                "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  CONNECT "localhost:4242/nothing")"        "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  CONNECT "localhost:4242/nothing.html")"   "501 Not Implemented"    ""

expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242")"                "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242/nothing")"        "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242/nothing.html")"   "501 Not Implemented"    ""

expect_eq_get "$(curl -is -X  TRACE "localhost:4242")"                  "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  TRACE "localhost:4242/nothing")"          "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  TRACE "localhost:4242/nothing.html")"     "501 Not Implemented"    ""

expect_eq_get "$(curl -is -X  PATCH "localhost:4242")"                  "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  PATCH "localhost:4242/nothing")"          "501 Not Implemented"    ""
expect_eq_get "$(curl -is -X  PATCH "localhost:4242/nothing.html")"     "501 Not Implemented"    ""

## invalid method: 400
expect_eq_get "$(curl -is -X  nothing "localhost:4242")"                "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  nothing "localhost:4242/nothing")"        "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  nothing "localhost:4242/nothing.html")"   "400 Bad Request"           ""

expect_eq_get "$(curl -is -X  "" "localhost:4242")"                     "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  "" "localhost:4242/nothing")"             "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  "" "localhost:4242/nothing.html")"        "400 Bad Request"           ""


# 502
## >> test_gci.sh


# 505
## not suppored http-version: 505
expect_eq_get "$(echo -en "GET / HTTP/1.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/1.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/1.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""

expect_eq_get "$(echo -en "GET / HTTP/2.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/2.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/2.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""

expect_eq_get "$(echo -en "GET / HTTP/3.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/3.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/3.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""


tear_down

################################################################################

echo
echo "================================================================"
echo " *** ERROR RESULT ***"
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


echo -n "  Defunct Process: "
if [ $defunct_generated -eq $FALSE ]; then
    echo -e "-"
else
    echo -e "${RED}$defunct_count defunct process${RESET}"
    exit_status=$FAILURE
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
