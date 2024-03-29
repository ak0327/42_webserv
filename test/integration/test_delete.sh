#!/bin/bash

source test/integration/test_func.sh
source test/integration/prepare_test_file.sh

################################################################################

CONF_PATH="test/integration/integration_test.conf"
TEST_DIR="test/integration/"

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

fd_before=0
fd_after=0

################################################################################

start_up "DELETE TEST"

################################################################################

# func            $1:host    $2:port $3:target            $4:check_file_path        $5:expect status          $6:expect_delete

expect_eq_delete "localhost" "4242" "/upload/hello.txt"   "html/upload/hello.txt"   "204 No Content"          true
expect_eq_delete "localhost" "4242" "/upload/index.html"  "html/upload/index.html"  "204 No Content"          true
expect_eq_delete "localhost" "4242" "/upload/sub/a.txt"   "html/upload/sub/a.txt"   "204 No Content"          true

expect_eq_delete "localhost" "4242" "/upload/nothing"     ""                        "404 Not Found"           false
expect_eq_delete "localhost" "4242" "/upload/"            "html/upload/"            "404 Not Found"           false # upload/index.html nothing
expect_eq_delete "localhost" "4242" "/upload/sub/"        "html/upload/sub/"        "404 Not Found"           false # upload/dir/index.html nothing

expect_eq_delete "localhost" "4242" "/"                   "html/index.html"         "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/../../../"          "html/index.html"         "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/index.html"         "html/index.html"         "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/404.html"           "html/404.html"           "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/cgi-bin/hello.py"   "html/cgi-bin/hello.py"   "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/a/b/c/"             "html/a/b/c/file_c.html"  "405 Method Not Allowed"  false
expect_eq_delete "localhost" "4242" "/a/b/c/d/"           ""                        "405 Method Not Allowed"  false # a/b/c/d not found

################################################################################

tear_down

################################################################################

echo
echo "================================================================"
echo " *** DELETE RESULT ***"

exit_status=1
if [ $ng_cnt -eq 0 ] && [ $skip_cnt -eq 0 ]; then
    echo -e " ${GREEN}All tests passed successfully${RESET}"
    exit_status=0
fi

echo "  Total Tests    : $test_cnt"

echo "  Failed Tests   : $ng_cnt"

if [ $ng_cnt -gt 0 ]; then
    for case in "${ng_cases[@]}"; do
        echo -e "${RED}     $case${RESET}"
    done
fi


echo "  Skipped Tests  : $skip_cnt"

if [ $skip_cnt -gt 0 ]; then
    for case in "${skip_cases[@]}"; do
        echo -e "${YELLOW}     $case${RESET}"
    done
fi


echo -n "  Defunct Process: "
if [ $defunct_generated -eq $FALSE ]; then
    echo -e "-"
else
    echo -e "${RED}$defunct_count defunct process${RESET}"
    exit_status=$FAILURE
fi


echo -n "  Fd             : "
if [ $fd_before -eq $fd_after ]; then
    echo -e "-"
else
    echo -e "${RED}fd: $fd_before -> $fd_after${RESET}"
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
