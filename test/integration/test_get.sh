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

start_up "GET TEST"

################################################################################

# 200 OK
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /// HTTP/1.1\r\nHost: localhost\r\n\r\n"         | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /.//../../ HTTP/1.1\r\nHost: localhost\r\n\r\n"  | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost:  localhost   \r\n\r\n"       | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n"           | nc localhost 4242)"   "200 OK"    "html/index.html"
expect_eq_get "$(echo -en "GET /%2E%2E/ HTTP/1.1\r\nHost: localhost\r\n\r\n"    | nc localhost 4242)"   "200 OK"    "html/index.html"

expect_eq_get "$(curl -is "localhost:4242/hello.py")"     "200 OK"    "html/hello.py"
expect_eq_get "$(curl -is "localhost:4242/index.css")"    "200 OK"    "html/index.css"
expect_eq_get "$(curl -is "localhost:4242/404.html")"     "200 OK"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/50x.html")"     "200 OK"    "html/50x.html"
expect_eq_get "$(curl -is "localhost:4242/new.html")"     "200 OK"    "html/new.html"

#expect_eq_get "$(curl -is "localhost:4242/images/image1.jpg")"   "200 OK"   "html/images/image1.jpg"  // can't validate diff as string -> diff file
expect_eq_get "$(curl -is "localhost:4242/a/b/c/")"       "200 OK"    "html/a/b/c/file_c.html"


expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py")"                         "200 OK"          "html/cgi-bin/hello.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py?query")"                   "200 OK"          "html/cgi-bin/hello.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/post_simple.py")"                   "200 OK"          "html/cgi-bin/post_simple.py"
expect_eq_get "$(curl -is -X GET --data "request body ignored" localhost:4242/cgi-bin/post_simple.py)"  "200 OK"   "html/cgi-bin/post_simple.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_400.py")"                     "200 OK"          "html/cgi-bin/hello_400.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_404.py")"                     "200 OK"          "html/cgi-bin/hello_404.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_no_shebang.py")"              "200 OK"          "html/cgi-bin/error_no_shebang.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/error_wrong_shebang.py")"           "200 OK"          "html/cgi-bin/error_wrong_shebang.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/exit1.py")"                         "200 OK"          "html/cgi-bin/exit1.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_invalid_header.py")"          "200 OK"          "html/cgi-bin/hello_invalid_header.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello_500.py")"                     "200 OK"          "html/cgi-bin/hello_500.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_loop.py")"                 "200 OK"          "html/cgi-bin/infinite_loop.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/infinite_print.py")"                "200 OK"          "html/cgi-bin/infinite_print.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep5sec.py")"                     "200 OK"          "html/cgi-bin/sleep5sec.py"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/sleep10sec.py")"                    "200 OK"          "html/cgi-bin/sleep10sec.py"

expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.py/path/info")"               "404 Not Found"   "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/nothing.py")"                       "404 Not Found"   "html/404.html"


# redirect -> todo: location
expect_eq_get "$(curl -is "localhost:4242/old.html")"           "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/old/")"               "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/autoindex_files")"    "301 Moved Permanently"    ""
expect_eq_get "$(curl -is "localhost:4242/upload")"             "301 Moved Permanently"    ""

#expect_eq_get "$(curl -isL "localhost:4242/old.html")"          "200 OK"    "html/new.html"
#expect_eq_get "$(curl -isL "localhost:4242/old/")"              "200 OK"    "html/new/index.html"


# 404 Not Found
expect_eq_get "$(curl -is "localhost:4242/nothing")"                    "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/")"                   "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing.html")"               "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/nothing.html")"       "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/a/b/c/nothing/")"             "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing")"                    "404 Not Found"    "html/404.html"
expect_eq_get "$(curl -is "localhost:4242/nothing/hoge/huga")"          "404 Not Found"    "html/404.html"


# 405 Method Not Allowed
expect_eq_get "$(curl -is "localhost:4242/delete_only/")"                 "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/index.html")"       "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/dir/")"             "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/dir/index.html")"   "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/nothing.html")"     "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/nothing.html")"     "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/post_only/")"                   "405 Method Not Allowed"    ""
expect_eq_get "$(curl -is "localhost:4242/delete_only/")"                 "405 Method Not Allowed"    ""


# 415
expect_eq_get "$(curl -is "localhost:4242/cgi-bin/hello.sh")"             "415 Unsupported Media Type"   ""


# 400 BadRequest
## invalid request line
expect_eq_get "$(echo -en "GET\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET /\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"                  "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"           "400 Bad Request"    ""
expect_eq_get "$(echo -en "  GET / \r\nHost: localhost\r\n\r\n" | nc localhost 4242)"               "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"       "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET / / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"       "400 Bad Request"    ""

## invalid method
expect_eq_get "$(echo -en "get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "Get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "get / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "hoge / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"    ""
expect_eq_get "$(echo -en " / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"            "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"     "400 Bad Request"    ""

## invalid request target
expect_eq_get "$(echo -en "GET . HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"         "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET .. HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"      "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET ../html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"   "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET ./html HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"    "400 Bad Request"    ""
expect_eq_get "$(echo -en "GET %2E HTTP/1.1\r\nHost: localhost\r\n\r\n" | nc localhost 4242)"       "400 Bad Request"  ""

## invalid herader
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\n\r\n" | nc localhost 4242)"                            "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\n\r\n\r\n\r\n" | nc localhost 4242)"                    "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost:\r\n\r\n" | nc localhost 4242)"                   "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost : localhost\r\n\r\n" | nc localhost 4242)"        "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"   ""
expect_eq_get "$(echo -en "GET / HTTP/1.1\r\nHost: a b c\r\n\r\n" | nc localhost 4242)"             "400 Bad Request"   ""


# permission
#expect_eq_get "$(curl -is "localhost:4242/permission/___.html")"        "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/__x.html")"        "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/_w_.html")"        "403 Forbidden"       ""  # mac vs linux
expect_eq_get "$(curl -is "localhost:4242/permission/r__.html")"        "200 OK"              "html/permission/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/rwx.html")"        "200 OK"              "html/permission/rwx.html"

expect_eq_get "$(curl -is "localhost:4242/permission/___/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/___/rwx.html")"    "403 Forbidden"       ""

#expect_eq_get "$(curl -is "localhost:4242/permission/__x/___.html")"    "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/__x/__x.html")"    "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/__x/_w_.html")"    "403 Forbidden"       ""  # mac vs linux
expect_eq_get "$(curl -is "localhost:4242/permission/__x/r__.html")"    "200 OK"              "html/permission/__x/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/__x/rwx.html")"    "200 OK"              "html/permission/__x/rwx.html"

expect_eq_get "$(curl -is "localhost:4242/permission/_w_/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/_w_/rwx.html")"    "403 Forbidden"       ""

expect_eq_get "$(curl -is "localhost:4242/permission/r__/___.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/__x.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/_w_.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/r__.html")"    "403 Forbidden"       ""
expect_eq_get "$(curl -is "localhost:4242/permission/r__/rwx.html")"    "403 Forbidden"       ""

#expect_eq_get "$(curl -is "localhost:4242/permission/rwx/___.html")"    "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/rwx/__x.html")"    "403 Forbidden"       ""  # mac vs linux
#expect_eq_get "$(curl -is "localhost:4242/permission/rwx/_w_.html")"    "403 Forbidden"       ""  # mac vs linux
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/r__.html")"    "200 OK"              "html/permission/rwx/r__.html"
expect_eq_get "$(curl -is "localhost:4242/permission/rwx/rwx.html")"    "200 OK"              "html/permission/rwx/rwx.html"


# server_name
expect_eq_get "$(curl -is -H "Host: webserv"  "localhost:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: a"        "localhost:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: b"        "localhost:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: c"        "localhost:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: nothing"  "localhost:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: d"        "localhost:4242/")"                   "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge"     "localhost:4242/")"                   "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge"     "localhost:4242/nothing")"            "404 Not Found"   "html/hoge/404.html"
expect_eq_get "$(curl -is -H "Host: huga"     "localhost:4242/nothing")"            "404 Not Found"   "html/404.html"

expect_eq_get "$(curl -is -H "Host: cgi_s"    "localhost:4343/")"                   "200 OK"          "html/index_cgi.html"
expect_eq_get "$(curl -is -H "Host: cgi_s"    "localhost:4343/cgi-bin/")"           "404 Not Found"   "html/404.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "localhost:4343/")"                   "200 OK"          "html/index_cgi.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "localhost:4343/nothing")"            "404 Not Found"   "html/404.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "localhost:4343/cgi-bin/hello.py")"   "200 OK"          "test/integration/cgi-result/hello.txt"


expect_eq_get "$(curl -is -H "Host: webserv"  "127.0.0.1:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: a"        "127.0.0.1:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: b"        "127.0.0.1:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: c"        "127.0.0.1:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: nothing"  "127.0.0.1:4242/")"                   "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: d"        "127.0.0.1:4242/")"                   "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge"     "127.0.0.1:4242/")"                   "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge"     "127.0.0.1:4242/nothing")"            "404 Not Found"   "html/hoge/404.html"
expect_eq_get "$(curl -is -H "Host: huga"     "127.0.0.1:4242/nothing")"            "404 Not Found"   "html/404.html"

expect_eq_get "$(curl -is -H "Host: cgi_s"    "127.0.0.1:4343/")"                   "200 OK"          "html/index_cgi.html"
expect_eq_get "$(curl -is -H "Host: cgi_s"    "127.0.0.1:4343/cgi-bin/")"           "404 Not Found"   "html/404.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "127.0.0.1:4343/")"                   "200 OK"          "html/index_cgi.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "127.0.0.1:4343/nothing")"            "404 Not Found"   "html/404.html"
expect_eq_get "$(curl -is -H "Host: xxx"      "127.0.0.1:4343/cgi-bin/hello.py")"   "200 OK"          "test/integration/cgi-result/hello.txt"


expect_eq_get "$(curl -is -H "Host: old_server"   "localhost:3939/")"               "200 OK"          "html/dir_a/index.html"  # default: server_a
expect_eq_get "$(curl -is -H "Host: OLD_SERVER"   "localhost:3939/")"               "200 OK"          "html/dir_a/index.html"  # default: server_a
expect_eq_get "$(curl -is -H "Host: new_server"   "localhost:3939/")"               "200 OK"          "html/dir_a/index.html"  # default: server_a
expect_eq_get "$(curl -is -H "Host: xxx"          "localhost:3939/")"               "200 OK"          "html/dir_a/index.html"  # default: server_a
expect_eq_get "$(curl -is -H "Host: server_a"     "localhost:3939/")"               "200 OK"          "html/dir_a/index.html"  # default: server_a
expect_eq_get "$(curl -is -H "Host: server_b"     "localhost:3939/")"               "200 OK"          "html/dir_b/index.html"
expect_eq_get "$(curl -is -H "Host: server_c"     "localhost:3939/")"               "200 OK"          "html/dir_c/index.html"


expect_eq_get "$(curl -is -H "Host: old_server"   "localhost:4040/")"               "200 OK"          "html/old/index.html"
expect_eq_get "$(curl -is -H "Host: OLD_SERVER"   "localhost:4040/")"               "200 OK"          "html/old/index.html"
expect_eq_get "$(curl -is -H "Host: new_server"   "localhost:4040/")"               "200 OK"          "html/new/index.html"
expect_eq_get "$(curl -is -H "Host: xxx"          "localhost:4040/")"               "200 OK"          "html/new/index.html"  # default: new_server
expect_eq_get "$(curl -is -H "Host: server_a"     "localhost:4040/")"               "200 OK"          "html/dir_a/index.html"
expect_eq_get "$(curl -is -H "Host: server_b"     "localhost:4040/")"               "200 OK"          "html/dir_b/index.html"
expect_eq_get "$(curl -is -H "Host: server_c"     "localhost:4040/")"               "200 OK"          "html/dir_c/index.html"


# server_name and port
expect_eq_get "$(curl -is -H "Host: webserv:4242"  "localhost:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: a:4242"        "localhost:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: b:4242"        "localhost:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: c:4242"        "localhost:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: nothing:4242"  "localhost:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: d:4242"        "localhost:4242/")"              "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge:4242"     "localhost:4242/")"              "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge:4242"     "localhost:4242/nothing")"       "404 Not Found"   "html/hoge/404.html"
expect_eq_get "$(curl -is -H "Host: huga:4242"     "localhost:4242/nothing")"       "404 Not Found"   "html/404.html"

expect_eq_get "$(curl -is -H "Host: webserv:4242"  "127.0.0.1:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: a:4242"        "127.0.0.1:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: b:4242"        "127.0.0.1:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: c:4242"        "127.0.0.1:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: nothing:4242"  "127.0.0.1:4242/")"              "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: d:4242"        "127.0.0.1:4242/")"              "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge:4242"     "127.0.0.1:4242/")"              "200 OK"          "html/hoge/index.html"
expect_eq_get "$(curl -is -H "Host: hoge:4242"     "127.0.0.1:4242/nothing")"       "404 Not Found"   "html/hoge/404.html"
expect_eq_get "$(curl -is -H "Host: huga:4242"     "127.0.0.1:4242/nothing")"       "404 Not Found"   "html/404.html"

expect_eq_get "$(curl -is -H "Host: webserv:2121"  "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: a:2121"        "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: b:2121"        "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: c:2121"        "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: nothing:2121"  "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: d:2121"        "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: hoge:2121"     "localhost:4242/")"              "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: hoge:2121"     "localhost:4242/nothing")"       "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: huga:2121"     "localhost:4242/nothing")"       "400 Bad Request"  ""
expect_eq_get "$(curl -is -H "Host: huga:huga:ng"  "localhost:4242")"               "400 Bad Request"  ""


expect_eq_get "$(curl -is -H "Host: 127.0.0.1:4242"  "127.0.0.1:4242")"             "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: 127.0.0.1:4242"  "localhost:4242")"             "200 OK"          "html/index.html"
expect_eq_get "$(curl -is -H "Host: 127.0.0.1:4242"  "localhost:4242")"             "200 OK"          "html/index.html"

tear_down

################################################################################

echo
echo "================================================================"
echo " *** GET RESULT ***"
exit_status=$FAILURE

if [ $ng_cnt -eq 0 ] && [ $skip_cnt -eq 0 ]; then
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


echo "  Skipped Tests  : $skip_cnt"
if [ $skip_cnt -gt 0 ]; then
    for case in "${skip_cases[@]}"; do
        echo -n "     "
        echo -e "${YELLOW}${case}${RESET}"
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
