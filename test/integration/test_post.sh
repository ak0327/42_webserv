#!/bin/bash

source test/integration/test_func.sh

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

./webserv $CONF_PATH &

SERVER_PID=$!

sleep 1

################################################################################

test_post_upload "localhost:4242/upload/"  "html/cgi-bin/"   "hello.py"   "html/upload/hello.txt"   "201 Created"   true

################################################################################

kill $SERVER_PID

################################################################################

echo
echo "================================================================"
echo " *** RESULT ***"
exit_status=1
if [ $ng_cnt -eq 0 ] && [ $skip_cnt -eq 0 ]; then
    echo -e " ${GREEN}All tests passed successfully${RESET}"
    exit_status=0
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

exit $exit_status

################################################################################
