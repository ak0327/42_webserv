#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

SUCCESS=0

get_test="./test/integration/test_get.sh"
$get_test
if [ $? -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}]"
else
  echo -en "[${GREEN}NG${RESET}]"
fi
echo "$get_test"


post_test="./test/integration/test_post.sh"
$post_test
if [ $? -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}]"
else
  echo -en "[${GREEN}NG${RESET}]"
fi
echo "$post_test"

delete_test="./test/integration/test_delete.sh"
$delete_test
if [ $? -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}]"
else
  echo -en "[${GREEN}NG${RESET}]"
fi
echo "$delete_test"

cgi_test="./test/integration/test_cgi.sh"
$cgi_test
if [ $? -eq $SUCCESS ]; then
  echo -en "[${GREEN}OK${RESET}]"
else
  echo -en "[${GREEN}NG${RESET}]"
fi
echo "$cgi_test"
