#!/bin/bash

TRUE=1
FALSE=0

start_up() {
    local test_name=$1
    echo "================================================================"
    echo " $test_name"
    echo "================================================================"

    pkill webserv

    defunct_before=$(ps aux | grep defunct | grep -v grep | wc -l)

    prepare_test_file

    ./webserv $CONF_PATH 2>/dev/null &

    sleep 1
}


tear_down() {
    defunct_after=$(ps aux | grep defunct | grep -v grep | wc -l)
    defunct_count=$((defunct_after - defunct_before))
    if [ $defunct_count -eq 0 ]; then
      defunct_generated=$FALSE
    else
      defunct_generated=$TRUE
    fi


    process_count=$(ps aux | grep '[w]ebserv' | wc -l)
    if [ $process_count -eq 0 ]; then
      process_abort=$TRUE
    else
      process_abort=$FALSE
      pkill webserv
    fi
}


expect_eq_get() {
    local response=$1
    local expected_status=$2
    local expected_file=$3

    local call_line=${BASH_LINENO[0]}

    local filesize=$(stat -c "%s" "$path")

    local is_big_file=0
    if [ "$filesize" -ge $(( 1024 * 80 )) ]; then
        is_big_file=1
    fi

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
        local result
        result="Expected: \"$expected_start_line\", Actual: \"$actual_start_line\""
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [$result]")
        echo -e "${RED}NG -> $result${RESET}"
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

        if [ -z $is_big_file ]; then
            echo "${diff_output}"
        fi
        ((ng_cnt++))
        if [ -z $is_big_file ]; then
            ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG: [${response}]")
        else
            ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG: [...]")
        fi
    fi
}


expect_eq_curl() {
    local target=$1
    local expected_status=$2
    local expected_file=$3

    local call_line=${BASH_LINENO[0]}
    local response_file="${TEST_DIR}response.txt"

    echo "----------------------------------------------------------------"
    ((test_cnt++))
    echo "TEST No.${test_cnt} (L${call_line})"

    if [ -n "$expected_file" ] && [ ! -f "$expected_file" ]; then
        echo -e " ${YELLOW}Test No.${test_cnt} skipped: Expected file '$expected_file' not found${RESET}"
        ((skip_cnt++))
        skip_cases+=("No.${test_cnt} (L${call_line})")
        return
    fi

    curl -is "$target" > "$response_file" 2> /dev/null

    local actual_start_line
    actual_start_line=$(head -n 1 ${response_file} | tr -d '\r')

    local expected_start_line
    expected_start_line="HTTP/1.1 ${expected_status}"
#
    echo -n " Start-Line  : "
    if [ "$expected_start_line" == "$actual_start_line" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        result="Expected: \"$expected_start_line\", Actual: \"$actual_start_line\""
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [$result]")
        echo -e "${RED}NG -> $result${RESET}"
    fi


    local body_file="${expected_file}_test.txt"

    awk 'BEGIN{RS="\r\n"; FS="\n"; header=1} /^$/{header=0; next} !header' "$response_file" | perl -pe 'chomp if eof' > "$body_file"

#    echo "Response file:"
#    cat "$response_file" | wc -lc
#    echo "Body file:"
#    cat "$body_file" | wc -lc


    echo -n " Request-Body: "
    if [ -z "$expected_file" ]; then
        diff_output=$(diff -u <(echo -n "") "$body_file")
    else
        diff_output=$(diff -u "$expected_file" "$body_file")
    fi

    if [ -z "$diff_output" ]; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${RED}NG${RESET}"
        ((ng_cnt++))
#        ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG [$diff_output]")
        ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG")
    fi


#    local body_start_line=$(awk '/^\r$/{print NR + 1; exit}' ${response_file})
#    if [ -z "$body_start_line" ]; then
#        body_start_line=$(awk '/^$/{print NR + 1; exit}' ${response_file})
#    fi
#
#
#    echo -n " Request-Body: "
#    if [ -z "$expected_file" ]; then
#        diff_output=$(diff -u <(echo -n "") <(tail -n +${body_start_line} "${response_file}"))
#    else
#        diff_output=$(diff -u "${expected_file}" <(tail -n +${body_start_line} "${response_file}"))
#    fi
#
#    if [ -z "$diff_output" ]; then
#        echo -e "${GREEN}OK${RESET}"
#    else
#        echo -e "${RED}NG${RESET}"
#        echo "${diff_output}"
#        ((ng_cnt++))
#        ng_cases+=("No.${test_cnt} (L${call_line}): Request-Body NG: [${diff_output}]")
#    fi

#    rm -f ${body_file}
#    rm -f ${response_file}
}



test_post_upload() {
    local file_dir=$1
    local file_name=$2
    local url=$3
    local expected_status=$4
    local expect_created=$5

    local call_line=${BASH_LINENO[0]}
    local response_file="${TEST_DIR}response.txt"

    echo "----------------------------------------------------------------"
    ((test_cnt++))
    echo "TEST No.${test_cnt} (L${call_line})"

    local upload_path="html/upload/${file_name}"
    local src_path="$file_dir$file_name"

    local is_file_already_existed=0
    if [ -f "$upload_path" ]; then
      is_file_already_existed=1
    fi

    curl -i -F "file_name=@$src_path"  "${url}" > "$response_file" 2> /dev/null

    local actual_start_line
    actual_start_line=$(head -n 1 ${response_file} | tr -d '\r')

    local expected_start_line
    expected_start_line="HTTP/1.1 ${expected_status}"

    echo -n " Start-Line : "
    if [[ "$expected_start_line" == "$actual_start_line" ]]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        result="Expected: \"$expected_start_line\", Actual: \"$actual_start_line\""
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [$result]")
        echo -e "${RED}NG -> $result${RESET}"
    fi


    echo -n " UPLOAD     : "
    local is_created
    if [[ $is_file_already_existed == 0 && -f "$upload_path" ]]; then
      is_created="true"
    else
      is_created="false"
    fi


    if [[ "$expect_created" == "$is_created" ]]; then
        diff_output=$(diff $src_path $upload_path)

        if [[ -z "$diff_output" ]]; then
            echo -e "${GREEN}OK${RESET}"
        else
            ((ng_cnt++))
            ng_cases+=("No.${test_cnt} (L${call_line}): Upload NG: [${file_dir}${file_name}: $diff_output]")
            echo -e "${RED}NG${RESET}"
        fi
    else
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Upload NG: [${file_dir}${file_name}: expect_created:"$expect_created" created:"$is_created"]")
        echo -e "${RED}NG${RESET}"
    fi


    if [[ "$expect_created" == "true" ]] && [ -f "$upload_path" ]; then
        rm "$upload_path"
    fi

    [ -f "$response_file" ] && rm "$response_file"
}


expect_eq_delete() {
    local host=$1
    local port=$2
    local path=$3
    local check_file_path=$4

    local expected_status=$5
    local expected_delete=$6

    local response_file="${TEST_DIR}response.txt"

    local call_line=${BASH_LINENO[0]}

    echo "----------------------------------------------------------------"
    ((test_cnt++))
    echo "TEST No.${test_cnt} (L${call_line})"

    if [ -n "$check_file_path" ]; then
      touch "$check_file_path"
    fi

    local cmd
    cmd="-is -X DELETE ${host}:${port}${path}"
    curl $cmd > "$response_file"


    local actual_start_line
    actual_start_line=$(head -n 1 ${response_file} | tr -d '\r')

    local expected_start_line
    expected_start_line="HTTP/1.1 ${expected_status}"

    echo -n " Start-Line : "
    if [[ "$expected_start_line" == "$actual_start_line" ]]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        result="Expected: \"$expected_start_line\", Actual: \"$actual_start_line\""
        ng_cases+=("No.${test_cnt} (L${call_line}): Start-Line NG: [$result]")
        echo -e "${RED}NG -> $result${RESET}"
    fi


    echo -n " Delete     : "
    local is_deleted
    if [[ -z "$check_file_path" ]]; then
      is_deleted="false"
    elif [[ -f "$check_file_path" || -d "$check_file_path" ]]; then
      is_deleted="false"
    else
      is_deleted="true"
    fi

#    echo "path: $check_file_path -> is_deleted: $is_deleted, expected_delete: $expected_delete"

    if [[ "$expected_delete" == "$is_deleted" ]]; then
        echo -e "${GREEN}OK${RESET}"
    else
        ((ng_cnt++))
        ng_cases+=("No.${test_cnt} (L${call_line}): Delete NG: [${cmd}]")
        echo -e "${RED}NG${RESET}"
    fi


    if [[ "$expected_delete" == "true" ]] && [ -f "$check_file_path" ]; then
        [ -f $check_file_path ] && rm "$check_file_path"
    fi

    [ -f "$response_file" ] && rm "$response_file"
}
