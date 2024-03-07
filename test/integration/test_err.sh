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

# not supported method
expect_eq_get "$(curl -is -X  HEAD "localhost:4242")"                   "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  HEAD "localhost:4242/nothing")"           "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  HEAD "localhost:4242/nothing.html")"      "405 Method Not Allowed"    ""

expect_eq_get "$(curl -is -X  PUT "localhost:4242")"                    "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  PUT "localhost:4242/nothing")"            "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  PUT "localhost:4242/nothing.html")"       "405 Method Not Allowed"    ""

expect_eq_get "$(curl -is -X  CONNECT "localhost:4242")"                "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  CONNECT "localhost:4242/nothing")"        "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  CONNECT "localhost:4242/nothing.html")"   "405 Method Not Allowed"    ""

expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242")"                "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242/nothing")"        "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  OPTIONS "localhost:4242/nothing.html")"   "405 Method Not Allowed"    ""

expect_eq_get "$(curl -is -X  TRACE "localhost:4242")"                  "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  TRACE "localhost:4242/nothing")"          "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  TRACE "localhost:4242/nothing.html")"     "405 Method Not Allowed"    ""

expect_eq_get "$(curl -is -X  PATCH "localhost:4242")"                  "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  PATCH "localhost:4242/nothing")"          "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is -X  PATCH "localhost:4242/nothing.html")"     "405 Method Not Allowed"    ""


# invalid method
expect_eq_get "$(curl -is -X  nothing "localhost:4242")"                "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  nothing "localhost:4242/nothing")"        "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  nothing "localhost:4242/nothing.html")"   "400 Bad Request"           ""

expect_eq_get "$(curl -is -X  "" "localhost:4242")"                     "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  "" "localhost:4242/nothing")"             "400 Bad Request"           ""
expect_eq_get "$(curl -is -X  "" "localhost:4242/nothing.html")"        "400 Bad Request"           ""


# not suppored http-version
expect_eq_get "$(echo -en "GET / HTTP/1.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/1.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/1.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""

expect_eq_get "$(echo -en "GET / HTTP/2.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/2.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/2.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""

expect_eq_get "$(echo -en "GET / HTTP/3.0\r\nHost: host\r\n\r\n"              | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing HTTP/3.0\r\nHost: host\r\n\r\n"       | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""
expect_eq_get "$(echo -en "GET /nothing.html HTTP/3.0\r\nHost: host\r\n\r\n"  | nc localhost 4242)"   "505 HTTP Version Not Supported"    ""


# invalid http-version
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
