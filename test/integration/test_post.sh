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


SUCCESS=0
FAILURE=1

TRUE=1
FALSE=0

test_cnt=0

ng_cnt=0
ng_cases=()

skip_cnt=0
skip_cases=()

defunct_before=0
defunct_after=0
defunct_count=0
defunct_generated=$FALSE
process_abort=$FALSE

fd_before=0
fd_after=0

################################################################################

start_up "POST TEST"

################################################################################

# 201 Created
test_post_upload "html/cgi-bin/"  "hello.py"      "localhost:4242/upload/"  "201 Created"   true
#test_post_upload "html/cgi-bin/"  "page.php"      "localhost:4242/upload/"  "201 Created"   true

test_post_upload "html/images/"   "image1.jpg"    "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/images/"   "image2.jpeg"   "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/images/"   "image3.png"    "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/images/"   "image4.gif"    "localhost:4242/upload/"  "201 Created"   true

test_post_upload "html/big_size/" "1kB.txt"       "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/big_size/" "1MB.txt"       "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/big_size/" "10MB.txt"      "localhost:4242/upload/"  "201 Created"   true
test_post_upload "html/big_size/" "19MB.txt"      "localhost:4242/upload/"  "201 Created"   true


test_post_upload "html/big_size/" "20MB.txt"      "localhost:4242/upload/"  "413 Payload Too Large"   false
#test_post_upload "html/"          "hoge/"         "localhost:4242/upload/"  "400 Bad Request"         false # curl error
#test_post_upload "html/"          "nothing.html"  "localhost:4242/upload/"  "404 Not Found"           false


#test_post_upload "html/permission/"       "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/"       "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/"       "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
test_post_upload "html/permission/"       "r__.html"  "localhost:4242/upload/"  "201 Created" true
test_post_upload "html/permission/"       "rwx.html"  "localhost:4242/upload/"  "201 Created" true

#test_post_upload "html/permission/___/"   "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/___/"   "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/___/"   "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/___/"   "r__.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/___/"   "rwx.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#
#test_post_upload "html/permission/__x/"   "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/__x/"   "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/__x/"   "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
test_post_upload "html/permission/__x/"   "r__.html"  "localhost:4242/upload/"  "201 Created" true
test_post_upload "html/permission/__x/"   "rwx.html"  "localhost:4242/upload/"  "201 Created" true

#test_post_upload "html/permission/_w_/"   "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/_w_/"   "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/_w_/"   "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/_w_/"   "r__.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/_w_/"   "rwx.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#
#test_post_upload "html/permission/r__/"   "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/r__/"   "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/r__/"   "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/r__/"   "r__.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/r__/"   "rwx.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#
#test_post_upload "html/permission/rwx/"   "___.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/rwx/"   "__x.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
#test_post_upload "html/permission/rwx/"   "_w_.html"  "localhost:4242/upload/"  "400 Bad Request" false # curl error
test_post_upload "html/permission/rwx/"   "r__.html"  "localhost:4242/upload/"  "201 Created"     true
test_post_upload "html/permission/rwx/"   "rwx.html"  "localhost:4242/upload/"  "201 Created"     true


expect_eq_get "$(curl -is -H "Content-Length: 21" -X POST "localhost:4242/dir_a/")"                                         "413 Payload Too Large"    ""
expect_eq_get "$(curl -is -H "Content-Length: 21" -X POST "localhost:4242/dir_a/" --data "$(python3 -c "print('a'*21)")")"  "413 Payload Too Large"    ""
expect_eq_get "$(curl -is -X POST "localhost:4242/dir_a/" --data "$(python3 -c "print('a'*100)")")"                         "413 Payload Too Large"    ""



################################################################################

tear_down

################################################################################

echo
echo "================================================================"
echo " *** POST RESULT ***"

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


echo -n "  Defunct Process: "
if [ $defunct_generated -eq $FALSE ]; then
    echo -e "-"
else
    echo -e "${RED}$defunct_count defunct process${RESET}"
    exit_status=$FAILURE
fi


echo -n "  Fd             : "
if [ $fd_before -eq $fd_after ]; then
    echo -e "-"
else
    echo -e "${RED}fd: $fd_before -> $fd_after${RESET}"
    exit_status=$FAILURE
fi


echo -n "  Process Aborted: "
if [ $process_abort -eq $FALSE ]; then
    echo -e "-"
else
    echo -e "${RED}Aborted${RESET}"
    exit_status=$FAILURE
fi


echo "================================================================"
echo ""

clear_test_file

exit $exit_status

################################################################################
