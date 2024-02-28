#!/bin/bash

expect_eq_get() {
    local response=$1
    local expected_status=$2
    local expected_file=$3

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

    local actual_start_line
    actual_start_line=$(echo "$response" | head -n 1 | tr -d '\r')

    local expected_start_line
    expected_start_line="HTTP/1.1 ${expected_status}"

    echo -n " Start-Line  : "
    if [ "$expected_start_line" == "$actual_start_line" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [${request}]")
        echo -e "${RED}NG -> Expected: \"$expected_start_line\", Actual: \"$actual_start_line\"${RESET}"
    fi


    local body_start_line
    body_start_line=$(echo "${response}" | awk '/^\r$/{print NR + 1; exit}')
    if [ -z "$body_start_line" ]; then
        body_start_line=$(echo "${response}" | awk '/^$/{print NR + 1; exit}')
    fi

    echo -n " Request-Body: "
    if [ -z "$expected_file" ]; then
        diff_output=$(diff -u <(echo -n "") <(echo "${response}" | tail -n +${body_start_line}))
    else
        diff_output=$(diff -u "${expected_file}" <(echo "${response}" | tail -n +${body_start_line}))
    fi

    if [ -z "$diff_output" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${RED}NG${RESET}"
        echo "${diff_output}"
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG: [${response}]")
    fi
}
