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

start_up "CGI TEST"

################################################################################

# CGI
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello.py")"                         "200 OK"   "test/integration/cgi-result/hello.txt"

expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello.py?query")"                   "200 OK"   "test/integration/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello.py/path/info")"               "200 OK"   "test/integration/cgi-result/hello.txt"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/post_simple.py")"                   "200 OK"   "test/integration/cgi-result/post_simple_get.txt"
expect_eq_get "$(curl -is -X GET --data "request body ignored" localhost:4343/cgi-bin/post_simple.py)"  "200 OK"   "test/integration/cgi-result/post_simple_get.txt"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello.sh")"                         "200 OK"   "test/integration/cgi-result/hello.txt"


expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello_400.py")"             "400 Bad Request"             ""

expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello_404.py")"             "404 Not Found"               "html/404.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/nothing.py")"               "404 Not Found"               "html/404.html"

expect_eq_get "$(curl -is "localhost:4343/cgi-bin/error_no_shebang.py")"      "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/error_wrong_shebang.py")"   "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/exit1.py")"                 "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello_invalid_header.py")"  "500 Internal Server Error"   "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/hello_500.py")"             "500 Internal Server Error"   "html/50x.html"

expect_eq_get "$(curl -is "localhost:4343/cgi-bin/infinite_loop.py")"         "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/infinite_print.py")"        "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/sleep5sec.py")"             "504 Gateway Timeout"         "html/50x.html"
expect_eq_get "$(curl -is "localhost:4343/cgi-bin/sleep10sec.py")"            "504 Gateway Timeout"         "html/50x.html"


tear_down

################################################################################

echo
echo "================================================================"
echo " *** CGI RESULT ***"
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
