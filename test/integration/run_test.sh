#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

./test/integration/test_get.sh
get_result=$?

./test/integration/test_post.sh
post_result=$?

./test/integration/test_delete.sh
delete_result=$?


if [ $get_result -eq 0 ] && [ $post_result -eq 0 ] && [ $delete_result -eq 0 ]; then
  echo -e "${GREEN}All tests passed successfully${RESET}"
else
  echo -e "${RED}Some tests failed${RESET}"
  [ $get_result -ne 0 ] && echo -e "  ${RED}GET failed${RESET}"
  [ $post_result -ne 0 ] && echo -e "  ${RED}POST failed${RESET}"
  [ $delete_result -ne 0 ] && echo -e "  ${RED}DELETE failed${RESET}"
fi
