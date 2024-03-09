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

defunct_generated=$FALSE
process_abort=$FALSE


siege_test() {
    local concurrent=$1
    local time=$2
    local path=$3

    local call_line=${BASH_LINENO[0]}

    ((test_cnt++))
    echo -e "\nTEST No.${test_cnt} (L${call_line})"

    defunct_before=0
    defunct_after=0
    defunct_count=0
    fd_before=0
    fd_after=0
    test_ng=0

    pkill webserv

    sleep 1

    defunct_before=$(ps aux | grep defunct | grep -v grep | wc -l)

    ./webserv $CONF_PATH 2>/dev/null &

    sleep 1

    fd_before=$(lsof -p $(pgrep webserv) | wc -l)

#    echo "defunct_before:$defunct_before"
#    echo "fd_before     :$fd_before"

    siege --benchmark --concurrent="$concurrent" --time="$time" "$path" > /dev/null 2>&1

    sleep 5

    defunct_after=$(ps aux | grep defunct | grep -v grep | wc -l)
    defunct_count=$((defunct_after - defunct_before))
    if [ $defunct_count -eq 0 ]; then
      defunct_generated=$FALSE
    else
      defunct_generated=$TRUE
    fi

    fd_after=$(lsof -p $(pgrep webserv) | wc -l)

    process_count=$(ps aux | grep '[w]ebserv' | wc -l)
    if [ $process_count -eq 0 ]; then
      process_abort=$TRUE
    else
      process_abort=$FALSE
      pkill webserv
    fi

#    echo "defunct_after:$defunct_after"
#    echo "fd_after     :$fd_after"


    if [ $defunct_generated -eq $FALSE ]; then
        echo -e " [${GREEN}OK${RESET}] Defunct Process"
    else
        echo -e " [${RED}NG${RESET}] Defunct Process: $defunct_count defunct process generated"
        test_ng=1
    fi


    if [ $fd_before -eq $fd_after ]; then
        echo -e " [${GREEN}OK${RESET}] Fd"
    else
        echo -e " [${RED}NG${RESET}] Fd: $fd_before -> $fd_after"
        test_ng=1
    fi


    if [ $process_abort -eq $FALSE ]; then
        echo -e " [${GREEN}OK${RESET}] Process Running"
    else
        echo -e " [${RED}NG${RESET}] Process Aborted"
        test_ng=1
    fi

    if [ $test_ng -ne 0 ]; then
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): NG")
    fi
}


################################################################################
echo "================================================================"
echo " SIEGE TEST"
echo "================================================================"

################################################################################


siege_test 8 5s "http://localhost:4343/"
siege_test 8 5s "http://localhost:4343/nothing.html"
siege_test 8 3s "http://localhost:4343/cgi-bin/hello.py"
siege_test 8 3s "http://localhost:4343/cgi-bin/wrong_path.py"


siege_test 128 30s "http://localhost:4343/"
siege_test 128 30s "http://localhost:4343/cgi-bin/hello.py"
siege_test 128 30s "http://localhost:4343/cgi-bin/nothing.html"
siege_test 128 30s "http://localhost:4343/cgi-bin/infinite_loop.py"
siege_test 128 30s "http://localhost:4343/cgi-bin/infinite_print.py"
siege_test 128 30s "http://localhost:4343/cgi-bin/out_of_range.py"
siege_test 128 30s "http://localhost:4343/cgi-bin/error_no_shebang.py"
siege_test 128 30s "http://localhost:4343/cgi-bin/sleep?60"
siege_test 128 30s "http://localhost:4343/cgi-bin/wrong_path.py"


siege_test 255 60s "http://localhost:4343/"
siege_test 255 60s "http://localhost:4343/cgi-bin/hello.py"
siege_test 255 60s "http://localhost:4343/cgi-bin/nothing.html"
siege_test 255 60s "http://localhost:4343/cgi-bin/infinite_loop.py"
siege_test 255 60s "http://localhost:4343/cgi-bin/infinite_print.py"
siege_test 255 60s "http://localhost:4343/cgi-bin/out_of_range.py"
siege_test 255 60s "http://localhost:4343/cgi-bin/error_no_shebang.py"
siege_test 255 60s "http://localhost:4343/cgi-bin/sleep?60"
siege_test 255 60s "http://localhost:4343/cgi-bin/wrong_path.py"


################################################################################

echo
echo "================================================================"
echo " *** SIEGE RESULT ***"
exit_status=$FAILURE

exit_status=$FAILURE

if [ $ng_cnt -eq 0 ]; then
    echo -e " ${GREEN}All tests passed successfully${RESET}"
    exit_status=$SUCCESS
fi

echo "  Total Tests    : $test_cnt"

echo "  Failed Tests   : $ng_cnt"
if [ $ng_cnt -gt 0 ]; then
    for case in "${ng_cases[@]}"; do
        echo -n "     "
        echo -e "${RED}${case}${RESET}"
    done
fi


echo -e "================================================================\n"

exit $exit_status

################################################################################
