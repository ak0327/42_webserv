#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

SUCCESS=0

./test/integration/test_get.sh
get_result=$?

./test/integration/test_post.sh
post_result=$?

./test/integration/test_delete.sh
delete_result=$?

if [ $get_result -eq $SUCCESS ] && [ $post_result -eq $SUCCESS ] && [ $delete_result -eq $SUCCESS ]; then
  echo -e "${GREEN}All tests passed successfully${RESET}"
else
  echo -e "${RED}Some tests failed${RESET}"
  [ $get_result -ne $SUCCESS ] && echo -e "  ${RED}GET failed${RESET}"
  [ $post_result -ne $SUCCESS ] && echo -e "  ${RED}POST failed${RESET}"
  [ $delete_result -ne $SUCCESS ] && echo -e "  ${RED}DELETE failed${RESET}"
fi
