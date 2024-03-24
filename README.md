# 1. Overview
Implement an HTTP server like NGINX

<br>
<hr>  

# 2. How to use
## 2-1) Clone and compile
```shell
git clone git@github.com:ak0327/42_webserv.git
cd 42_webserv
make
```
<br>

## 2-2) Execute
```shell
./webserv [path_to_configuration_file.conf]
```
* If `path_to_configuration_file.conf` is omitted, read the default conf `conf/webserv.conf`

<br>
<hr>  

# 3. Configuration
## 3-1) file name, path
* named: `<file_name>.conf`
* placed in: `PJ_root/conf`

## 3-2) Blocks and Directives
* block
    - `http`
    - `server`
    - `location`


* directive
    - `listen`
    - `server_name`
    - `error_page`
    - `client_max_body_size`
    - `rewrite or return`
    - `root`
    - `autoindex`
    - `index`
    - `limit_except`
      - `deny`
      - `allow`
    - `cgi_mode`
    - `cgi_extension`
    - `cgi_timeout`
    - `recv_timeout`
    - `send_timeout`
    - `keepalive_timeout`
    - `session_timeout`

## 3-3) Syntax
### 3-3-1) Block
* http block
  ```
  http_block = [
  *(SP / LF)  "http"                    1*(SP / LF)  "{"  1*(SP / LF)
                       *server_block                      1*(SP / LF)
            "}"                                           1*(SP / LF) ]
  ``` 

<br>

* server block
  ```
  server_block = [
  "server"                  1*(SP / LF)  "{"  1*(SP / LF)
           *location_block                    1*(SP / LF)
           *directive_line                    1*(SP / LF)
  "}"                                         1*(SP / LF) ]
  ```
<br>
  
* location block
  ```
  location_block = [
  "location"  1*(SP / LF)  pattern     URI   1*(SP / LF)  "{"  1*(SP / LF)
                           *directive_line                     1*(SP / LF)
  "}"                                                          1*(SP / LF) ]
  
  pattern = ("=" 1*SP / "^~" 1*SP / "")
  ```
<br>

### 3-3-2) Directive
* directive line
  ```
  directive_line = directive  1*SP  parameters  *SP  ";"
  parameters     = parameter  1*(SP parameter)
  ```
<br>
  
* Grammar
  - `SP` : ` ` (space)
  - `LF` : `\n`
  - `/` : or
  - `*X` : repeat `X` zero or more times
  - `n*X` : n or more repetitions of `X`.
  - `"string"` : string
  - `directive` : directive
  - `parameter` : parameter corresponding to the directive.

<br>

* Syntax
  * listen
    ```
    "listen" ( address[:port] / port ) [default_server]  ";"
    ```
    * Default: listen *:80 | *:8000;
    * Context: server


  * server_name
    ```
    "server_name" name ... ";"
    ```
    * Default: server_name "";
    * Context: server


  * error_page
    ```
    "error_page" code ... uri ";"
    300 <= code <= 599; except 499
    ```
    * Default: -
    * Context: http, server, location, if in location


  * client_max_body_size
    ```
    "client_max_body_size" size ";"
    ```
    * Default: client_max_body_size 1m;
    * Context: http, server, location
    * Setting size to 0
      * disables checking of client request body size
    * If the size in a request exceeds the configured value
      * the 413 (Request Entity Too Large) error is returned to the client


  * return
    ```
    "return" code [text] ";" 
    ```
    * return code URL;
    * return URL;
    * Default: —
    * Context: server, location, if


  * rewrite
    ```
    "rewrite" regex replacement ";"
    ```
    * Default: -
    * Context: server, location, if


  * root
    ```
    "root" path ";"
    ```
    * Default: root html;
    * Context: http, server, location, if in location
    * https://nginx.org/en/docs/http/ngx_http_core_module.html#root


  * autoindex
    ```
    "autoindex" on | off ";"
    ```
    * Default: autoindex off;
    * Context: http, server, location


  * index
    ```
    "index" file ... ";" 
    ```
    * Default: index index.html;
    * Context: http, server, location


<br>
<hr>  

# 4. Author
* [ak0327](https://github.com/ak0327)

<br>
<hr>  

# 5. Confirmed Environments
* Ubuntu 22.04.2 LTS (ARM64)
* MacOS OS Ventura 13.5 (ARM64)

<br>
<hr>  

# 6. References
* [HTTP Documentation](https://httpwg.org/specs/)
* [HTTP 日本語訳](https://triple-underscore.github.io/http-common-ja.html#index)
* [MDN docs](https://developer.mozilla.org/ja/)
* [nginx](https://github.com/nginx/nginx)
* [Module ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html)
* [nginx開発ガイド](https://mogile.web.fc2.com/nginx/dev/development_guide.html)
* [システムプログラム (2022年)](https://www.coins.tsukuba.ac.jp/~syspro/2022/)
* Michael Kerrisk, Linux プログラミングインタフェース(千住 治郎 訳), オライリージャパン
* 渋川 よしき, Real World HTTP, オライリージャパン
* 戸根 勤, ネットワークはなぜつながるのか 第2版, 日経BP社
* 前橋 和弥, 基礎からのWebアブリケーシヨン開発入門, 技術評論社
* Paul S.Hethmon, HTTP詳説(ファサード 訳), ピアソン・エデュケーション
