#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

SUCCESS=0

get_test="./test/integration/test_get.sh"
$get_test
get_test_result=$?


post_test="./test/integration/test_post.sh"
post_test_result=$?
$post_test


delete_test="./test/integration/test_delete.sh"
delete_test_result=$?
$delete_test


cgi_test="./test/integration/test_cgi.sh"
cgi_test_result=$?
$cgi_test



if [ $get_test_result -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}] "
else
  echo -en "[${RED}NG${RESET}] "
fi
echo "$get_test"


if [ $post_test_result -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}] "
else
  echo -en "[${RED}NG${RESET}] "
fi
echo "$post_test"


if [ $delete_test_result -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}] "
else
  echo -en "[${RED}NG${RESET}] "
fi
echo "$delete_test"


if [ $cgi_test_result -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}] "
else
  echo -en "[${RED}NG${RESET}] "
fi
echo "$cgi_test"
