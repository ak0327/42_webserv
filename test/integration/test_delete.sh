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

test_cnt=0

ng_cnt=0
ng_cases=()

skip_cnt=0
skip_cases=()

################################################################################

echo "================================================================"
echo " DELETE TEST"
echo "================================================================"

prepare_test_file

./webserv $CONF_PATH &

sleep 1

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

process_count=$(ps aux | grep '[w]ebserv' | wc -l)
if [ "$process_count" -eq 0 ]; then
  process_abort=$TRUE
else
  process_abort=$FALSE
  pkill webserv
fi

#echo "process_count:$process_count, abort:$process_abort"
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


echo -n "  Process Aborted: "
if [ $process_abort -eq $FALSE ]; then
    echo -e "OK"
else
    echo -e "${RED}Aborted${RESET}"
    exit_status=$FAILURE
fi


echo "================================================================"
echo ""

clear_test_file

exit $exit_status

################################################################################
