# nginx conf error


## Syntax error

## OK
### OK
```nginx.conf
events {
}

http {
}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### OK
```nginx.conf
events {}
http{}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### OK
```nginx.conf
events
{

}

  http
{

}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### events only
```nginx.conf
events {
}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


<hr>

## NG

### empty
* syntax validation -> XXX validation -> test result
```nginx.conf

```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: [emerg] no "events" section in configuration
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### no events
```nginx.conf
http {
}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: [emerg] no "events" section in configuration
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### events duplicated
```nginx.conf
events {
}
events {
}
```
```shell
$ nginx -t
nginx: [emerg] "events" directive is duplicate in /opt/homebrew/etc/nginx/nginx.conf:3
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### events in events
```nginx.conf
events {
events {
}
}
```
```shell
$ nginx -t
nginx: [emerg] "events" directive is not allowed here in /opt/homebrew/etc/nginx/nginx.conf:2
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### http in events
```nginx.conf
events {
http {
}
}

http {
}
```
```shell
$ nginx -t
nginx: [emerg] "http" directive is not allowed here in /opt/homebrew/etc/nginx/nginx.conf:2
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### http duplicated
```nginx.conf
events {
}

http {
}
http {
}
```
```shell
$ nginx -t
nginx: [emerg] "http" directive is duplicate in /opt/homebrew/etc/nginx/nginx.conf:6
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### server out of http
```nginx.conf
events {
}

http {
}

server {
}
```
```shell
$ nginx -t
nginx: [emerg] "server" directive is not allowed here in /opt/homebrew/etc/nginx/nginx.conf:7
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```


### server conflicted
* initial value
  * server name: `""`
  * port: `0.0.0.0:8000`
* 重複した場合は無視される？
```nginx.conf
events {
}

http {

server {
}

server {
}

}
```
```shell
$ nginx -t
nginx: [warn] conflicting server name "" on 0.0.0.0:8000, ignored
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


## Quote
### `"`,`'`の扱い
* ""は文字列と認識されない
* ''も同様
* 外側のquoteは外される
* ''' -> [emerg] unexpected "'"
* """ -> [emerg] unexpected """
```nginx.conf
events {
}

http {

server {
    server_name a;
}

server {
    server_name "a";
}

}
```
```shell
$ nginx -t
nginx: [warn] conflicting server name "a" on 0.0.0.0:8000, ignored
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```

### `"`の扱い
* ''も同様
```nginx.conf
events {
}

http {

server {
    server_name '"a"';
}

server {
    listen 8000;
    server_name "'a'" '"a"';
}

}
```
```shell
$ nginx -t
nginx: [warn] conflicting server name ""a"" on 0.0.0.0:8000, ignored
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```

### quote
* quote removal後の結合は行われない
* server_nameはquote removal後にdelimiterがなければNG
```nginx.conf
events {
}

http {

server {
    server_name ab;
}

server {
    listen 8000;
    server_name "a"'b';
}

}
```
```shell
$ nginx -t
nginx: [emerg] unexpected "'" in /opt/homebrew/etc/nginx/nginx.conf:12
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test failed
```



### title
* port異なればwarnなし
```nginx.conf
events {
}

http {

server {
    listen 80;
    server_name a;
}

server {
    listen 81;
    server_name "a";
}

}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### title
```nginx.conf
events {
}

http {

server {
    server_name a;
}

server {
    listen 8000;
    server_name "a";
}

}
```
```shell
$ nginx -t
nginx: [warn] conflicting server name "a" on 0.0.0.0:8000, ignored
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


## server_name
* quoted printable charの使用可否
  ```python
  for i in range(256):
    c = chr(i)
    if not c.isprintable():
        continue
    single = "'"
    double = '"'
    print(single, c, single, sep='')
    print(double, c, double, sep='')
  ```
  * `\`
    * エスケープで文字列の判定部分がずれ、想定外の箇所でエラーになる
    * 扱いが面倒なので禁止文字とする
    * `"\"`
    * `'\'`
  * emerg
    * `\`でエスケープすれば使用可能だった
    * `*`以外は異種quoteで文字列と認識した`"'~'"`
      * `"""`
      * `'''`
      * `"*"`
      * `'*'`
      * `"~"`
      * `'~'`
  * warn
    * `/`はescapeの有無によらずsuspicious
    * `a/b`, `/root`でもwarn -> `/`を含んでいるとwarn
    * warnではなくerrorにする方が楽かも
    * nginx: [warn] server name "/" has suspicious symbols in /opt/homebrew/etc/nginx/nginx.conf:382 
    * nginx: [warn] server name "/" has suspicious symbols in /opt/homebrew/etc/nginx/nginx.conf:382


```nginx.conf
events {
}

http {

server {
    server_name "a"
    'b';
}

}
```
```shell
$ nginx -t
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


### title
```nginx.conf
events {
}

http {

server {
    server_name "a"
    'b' c
    ;
}

server {
    server_name C;
}

}

```
```shell
$ nginx -t
nginx: [warn] conflicting server name "c" on 0.0.0.0:8000, ignored
nginx: the configuration file /opt/homebrew/etc/nginx/nginx.conf syntax is ok
nginx: configuration file /opt/homebrew/etc/nginx/nginx.conf test is successful
```


## listen
* OK : `listen 80;listen 81;`

### valid port
* 1 <= port <= 65535
* 00000000000001
* "1"


### invalid port
* 0
* 65536
* nginx: [emerg] invalid port in "0" of the "listen" directive in /opt/homebrew/etc/nginx/nginx.conf:7


### host not found
* `-1`
* `+00000000000001`
* `'1'`
* `"""`
* nginx: [emerg] host not found in "-1" of the "listen" directive in /opt/homebrew/etc/nginx/nginx.conf:7


### invalid parameter
* `80 81`
* nginx: [emerg] invalid parameter "81" in /opt/homebrew/etc/nginx/nginx.conf:7

### bind error
* `1.0`
  * nginx: [emerg] bind() to 1.0.0.0:80 failed (49: Can't assign requested address)

  




<hr>

# directive grammar
## listen
```
"listen" ( address[:port] / port ) [default_server]  ";"
```
* cf) nginx syntax
  ```
  listen address[:port]
   [default_server]
   [ssl]
   [http2 | quic]
   [proxy_protocol]
   [setfib=number]
   [fastopen=number]
   [backlog=number]
   [rcvbuf=size]
   [sndbuf=size]
   [accept_filter=filter]
   [deferred]
   [bind]
   [ipv6only=on|off]
   [reuseport]
   [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
  
  listen port
   [default_server]
   [ssl]
   [http2 | quic]
   [proxy_protocol]
   [setfib=number]
   [fastopen=number]
   [backlog=number]
   [rcvbuf=size]
   [sndbuf=size]
   [accept_filter=filter]
   [deferred]
   [bind]
   [ipv6only=on|off]
   [reuseport]
   [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
  
  listen unix:path
   [default_server]
   [ssl]
   [http2 | quic]
   [proxy_protocol]
   [backlog=number]
   [rcvbuf=size]
   [sndbuf=size]
   [accept_filter=filter]
   [deferred]
   [bind]
   [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
  ```
* Default: listen *:80 | *:8000;
* Context: server
* https://nginx.org/en/docs/http/ngx_http_core_module.html#listen

## server_name
```
"server_name" name ... ";"
```
* Default: server_name "";
* Context: server
* https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name

## error_page
```
"error_page" code ... uri ";"
300 <= code <= 599; except 499
```
```
"error_page" code ... [=[response]] uri ";"
```
* Default: -
* Context: http, server, location, if in location
* https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page

## https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name
```
"client_max_body_size" size ";"
```
* Default: client_max_body_size 1m;
* Context: http, server, location
* Setting size to 0
  * disables checking of client request body size
* If the size in a request exceeds the configured value
  * the 413 (Request Entity Too Large) error is returned to the client
* https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size

## return
```
"return" code [text] ";" 
```
* return code URL; 
* return URL; 
* Default: — 
* Context: server, location, if

* https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return
* 

## rewrite
```
"rewrite" regex replacement ";"
```
```
"rewrite" regex replacement [flag] ";"
```
* Default: -
* Context: server, location, if
* https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite


## root
```
"root" path ";"
```
* Default: root html; 
* Context: http, server, location, if in location
* https://nginx.org/en/docs/http/ngx_http_core_module.html#root

## autoindex
```
"autoindex" on | off ";"
```
* Default: autoindex off; 
* Context: http, server, location
* https://nginx.org/en/docs/http/ngx_http_autoindex_module.html#autoindex

## index
```
"index" file ... ";" 
```
* Default: index index.html; 
* Context: http, server, location
* https://nginx.org/en/docs/http/ngx_http_index_module.html#index










### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```


### title
```nginx.conf

```
```shell

```
