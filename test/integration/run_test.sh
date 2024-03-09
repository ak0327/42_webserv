#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

SUCCESS=0

#get_test="./test/integration/test_get.sh"
#$get_test
#get_res=$?
#
#
#post_test="./test/integration/test_post.sh"
#$post_test
#post_res=$?
#
#
#delete_test="./test/integration/test_delete.sh"
#$delete_test
#delete_res=$?
#
#
#cgi_test="./test/integration/test_cgi.sh"
#$cgi_test
#cgi_res=$?
#
#
#err_test="./test/integration/test_err.sh"
#$err_test
#err_res=$?
#
#
siege_test="./test/integration/test_siege.sh"
$siege_test
siege_res=$?




#if [ $get_res -eq $SUCCESS ]; then
#  echo -en " [${GREEN}OK${RESET}] "
#else
#  echo -en " [${RED}NG${RESET}] "
#fi
#echo "$get_test"
#
#
#if [ $post_res -eq $SUCCESS ]; then
#  echo -en " [${GREEN}OK${RESET}] "
#else
#  echo -en " [${RED}NG${RESET}] "
#fi
#echo "$post_test"
#
#
#if [ $delete_res -eq $SUCCESS ]; then
#  echo -en " [${GREEN}OK${RESET}] "
#else
#  echo -en " [${RED}NG${RESET}] "
#fi
#echo "$delete_test"
#
#
#if [ $cgi_res -eq $SUCCESS ]; then
#  echo -en " [${GREEN}OK${RESET}] "
#else
#  echo -en " [${RED}NG${RESET}] "
#fi
#echo "$cgi_test"
#
#
#if [ $err_res -eq $SUCCESS ]; then
#  echo -en " [${GREEN}OK${RESET}] "
#else
#  echo -en " [${RED}NG${RESET}] "
#fi
#echo "$err_test"


if [ $siege_res -eq $SUCCESS ]; then
  echo -en " [${GREEN}OK${RESET}] "
else
  echo -en " [${RED}NG${RESET}] "
fi
echo "$siege_test"

#total_res=$((get_res + post_res + delete_res + cgi_res + err_res + siege_res))
total_res=$((siege_res))
if [ $total_res -ne 0 ]; then
    exit 1
fi

exit 0
