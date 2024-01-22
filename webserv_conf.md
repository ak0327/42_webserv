# Specification of Configuration file

## 1. Specification of NGINX conf

### 1-1) file name, path
* named: `nginx.conf`
* placed in: `/usr/local/nginx/conf`, `/etc/nginx`, or `/usr/local/etc/nginx`.

### 1-2) Configuration File’s Structure
* simple direcvive
  - consists of the `name` and `parameters` separated by `spaces`
  - ends with a `semicolon ;`

* block directive
  - consists of the `name` and `parameters` separated by `spaces`
  - ends with a set of additional instructions surrounded by `braces ({ and })`
  - If a block directive can have other directives inside braces, it is called a `context`
  - examples: events, http, server, and location
  
* main context
  - Directives placed in the configuration file outside of any contexts
  - The `events` and `http` directives reside in the `main` context 
  - `server` in `http`, and `location` in `server`. 
  - `http` block 
    - グローバル設定や複数の `server` ブロックを含むことができる 
    - 通常、全体の設定（例えばログのフォーマットや接続タイムアウトなど）をこのレベルで設定する
    - `server` block 
      - `http` ブロック内に配置され、特定のサーバー（または仮想ホスト）に関する設定を行う
      - 一つの `http` ブロック内に複数の `server` ブロックを持つことができ、異なるドメイン名やポート番号でのリクエストを処理するために使用される
  - `location` block 
    - `server` ブロック内に配置され、特定のURIパターンに基づくリクエストの処理方法を指定する 
    - `location` ブロックは複数存在することができ、それぞれ異なるパスや条件に対応する 
  - 階層構造
    - 入れ子の深さについては、基本的に `http` > `server` > `location` の順で階層化される
    - `location` ブロック内にさらに `location` ブロックを入れることはできない
    - `server` ブロック内には複数の `location` ブロックを配置することが可能
    - `http` ブロックは通常、設定ファイルの最上位に配置されるため、その内部に他の `http` ブロックを入れることはできない


* comment
  - The rest of a line after the `#` sign


### 1-3) Serving Static Content
* data
  - HTML files: `/data/www`
  - images: `/data/images`

* server block
  - Request URI `/` -> `/data/www`
  - For example
    - Request URI stating with `/images/`
      - Request : `http://localhost/images/example.png`
      - Response: `/data/images/example.png`
        - no such file -> `404 error`
    - Request URI NOT starting with `/images/` -> mapped onto `/data/www` 
      - Request : `http://localhost/some/example.html`
      - Response: `/data/www/some/example.html`
  ```
  http {
    server {
      location / {
        root /data/www;
      }

      location /images/ {
        root /data;
      }
  
    }
  }  
  ```

* URIマッチング 
  - 正確なマッチ `=`
    - `location = /path`
    - URIが完全に一致する場合のみマッチ
    - 最も高いの優先順位
  - 優先的プレフィックスマッチ `^~`
    - `location ^~ /path`
    - URIが指定されたプレフィックスで始まる場合にマッチ
    - 正規表現よりも優先 
  - 正規表現マッチ `~`, `~*`
    - `location ~ /pattern` または `location ~* /pattern`
    - URIが指定された正規表現パターンにマッチする場合に適用
    - `~` は大文字小文字を区別、`~*` は区別しない
    - 非正規表現のプレフィックスマッチよりも優先 
  - 非正規表現プレフィックスマッチ 
    - `location /path`
    - URIが指定されたプレフィックスで始まる場合にマッチ
    - 最も低い優先順位



<hr>

## 2. Specification of webserv conf
### 2-1) subjectの解釈
- [ ] Choose the `port` and `host` of each `server` -> ***listen ディレクティブの解釈***
  - listenディレクティブによるport, hostの設定(server block)
    ```
    listen 80;               # 1. ポート80で全てのIPv4アドレスでリッスン
    listen [::]:80;          # 2. ポート80で全てのIPv6アドレスでリッスン
    listen 192.168.1.1:80;   # 3. ポート80で特定のIPv4アドレス（192.168.1.1）でリッスン
    ``` 
- [ ] Set up the `server_names` or `not` -> ***server_name ディレクティブの解釈***
  - The first server for a `host:port` will be the default for this `host:port`
  - means it will answer to all the requests that don’t belong to another server
  - `server_name`の設定(server block)
    ```
    server {
      server_name example.com www.example.com;
    }
    ```
  - `default_server`の設定(server block) 
    ```
    server {
      listen 80 default_server;  # デフォルトサーバーとして設定
      server_name _;             # 任意のホスト名に対するリクエストをキャッチ
    }
    ```
    - `server_name` が指定されていない場合、Nginxはこのサーバーブロックを全てのドメイン名やホスト名に対するデフォルトの応答として扱う
    - `server_name _;`は慣習的な記述方法で、挙動は`server_name`指定なしと同様
- [ ] Set up default error pages -> ***error_page ディレクティブの解釈***
  - error_pageの設定(server block)
    ```
    error_page 404 /custom_404.html;
    error_page 500 502 503 504 /custom_50x.html;
    ``` 
- [ ] Limit client body size -> ***client_max_body_size ディレクティブの解釈***
  - client_max_body_sizeの設定(server block) 
    ```
    client_max_body_size 2M;  # 最大2MBのボディサイズに制限
    ``` 
- Setup routes with one or multiple of the following rules/configuration
  - routes won't be using regexp
    - `1-3)` の正規表現マッチング`~`, `~*`以外の項目を解釈する
    - 優先順位：非正規表現 > 完全一致`=` > 前方一致`^~` とし、非正規表現の実装後に拡張していく
  - Define a list of accepted HTTP methods for the route
    - [ ] Define a HTTP redirection -> ***rewrite or return ディレクティブの解釈***
      * リソースの移動や削除、URLの変更によるリダイレクト
        - rewriteディレクティブによるリダイレクト(server block)
          ```
          rewrite ^/old-url$ /new-url permanent;  # 301 Moved Permanently
          rewrite ^/old-url$ /new-url redirect;   # 302 Found
          ```
          - rewrite ディレクティブでステータスコードを指定しない場合、デフォルトで 302 Found が使用される
        - returnディレクティブによるリダイレクト(server block)
          ```
          location /old-page {
            return 301 /new-page;        # 301 Moved Permanently
          }
          
          location /another-page {
            return 302 /temporary-page;  # 302 Found
          }
          ```
          - `return 201 /newpage` にすると、`/newpage`は文字列と解釈される
          - `301`などのレスポンスにより、UAは`/newpage`へのリクエストを発行する
  - [ ] Define a directory or a file from where the file should be searched -> ***root ディレクティブの解釈***
    * ex: url `/kapouet` is rooted to `/tmp/www`, url `/kapouet/pouic/toto/pouet` is `/tmp/www/pouic/toto/pouet`
    ```
    server {
      listen 80;
      server_name example.com;

      root /var/www/html;
    }
    ```
  - [ ] Turn on or off directory listing -> ***autoindex ディレクティブの解釈***
    ```
    location /some-directory/ {
      autoindex on;
    }
    ```
    - 特定の location ブロックに対してのみ有効にできる
    - 全体的に有効にする場合は、サーバーのルート設定に autoindex on; を追加（通常推奨されない）
  - [ ] Set a default file to answer if the request is a directory -> ***index ディレクティブの解釈***
    ```
    server {
      location / {
        index index.html index.php;
      }
    }
    ```
  - [ ] Make it work with POST and GET methods -> ***limit_except ディレクティブの解釈(不要かも)***
      ```
      location / {
        limit_except GET POST {
          deny all;
        }
      }
      ```
      - GET と POST メソッドのみを許可し、他のメソッドを拒否
      - defaultでPOST, GETを解釈するため、HTTP methodの制限が不要であれば、`limit_except`ディレクティブの解釈は不要かも？
      - `limit_except`はmethodの許可、拒否を明示できるが、webservでは要件外っぽい
  - [ ] Make the route able to accept uploaded files and configure where they should be saved
    ```
    location /uploads {
      client_max_body_size 20M;       # 最大アップロードサイズ
      root /path/to/upload/directory; # ファイル保存場所
    }
    ```
    * locationディレクティブ内で、client_max_body_sizeディレクティブを使用してアップロードサイズの制限を設定
    * rootディレクティブを使用してファイルの保存場所を指定
    * この構文はnginxでは使用不可
      * アップロードされたファイルを処理するために、通常バックエンドスクリプトが必要で、fastcgiなどを呼び出す必要があるため
      * ファイルアップロード処理の流れ 
        * クライアントからのアップロード: ユーザーがWebフォームなどを通じてファイルをアップロード
        * Nginxによるリクエストの受信: Nginxはアップロードされたファイルを含むHTTPリクエストを受け取る
        * リクエストの転送: Nginxはリクエストをバックエンドのアプリケーションサーバー（例: php-fpm、uwsgi など）に転送する
        * バックエンドスクリプトによる処理: バックエンドアプリケーションはファイルデータを受け取り、検証、処理（保存、変換、データベースへの記録など）を行う
  - [ ] Execute CGI based on certain file extension; for example php -> ***webserv_cgi ディレクティブの解釈***
    - nginxはfastcgiを使用するため、webservオリジナルのwebserv_cgiディレクティブを作成する
    - `webserv_cgi*` -> `fastcgi`への変更で、nginxでも使用可能
    - `include`ディレクティブなしで実行できるよう調整したい
    ```
    location ~ \.php$ {
        include webserv_cgi_params;
        webserv_cgi_pass 127.0.0.1:9000;  # ここはFastCGIサーバーのアドレス
        webserv_cgi_param SCRIPT_FILENAME $document_root$webserv_cgi_script_name;
        webserv_cgi_param PATH_INFO $webserv_cgi_path_info;
    }
    ```
    - [ ] CGI  use the full path as PATH_INFO
    - [ ] For chunked request, your server needs to un chunk it, the CGI will expect EOF as end of the body
    - [ ] Same things for the output of the CGI If no content_length is returned from the CGI, EOF will mark the end of the returned data
    - [ ] Your program should call the CGI with the file requested as first argument
    - [ ] The CGI should be run in the correct directory for relative path file access
    - [ ] Your server should work with one CGI (php-CGI, Python, and so forth)
- [ ] You must provide some configuration files and default basic files to test and demonstrate every feature works during evaluation



### 2-2) file name, path
* named: `*.conf`
  - subject P.4 Your executable will be run as follows: `./webserv [configuration file]`
* placed in: `PJ_root/conf`


### 2-3) 構文
* 必要十分の設定項目とするが、nginxと共用できる構文解釈とする
* CGI, POST(upload)はnginxと異なる構文となる
  * nginxはdefaultでスクリプトを実行できないため、FastCGIなどを使用する必要があるため
  * Apacheはスクリプトの直接的な実行をサポートしているらしい
* webservで解釈する必要があるブロック、ディレクティブとその記述方法は`2-1)`の通り
  * 解釈するブロックを以下に列挙する（順不同）
    - `http`
    - `server`
    - `location`
    - `event` (webservでは不使用だが、nginxと設定ファイルと共通化するために必要)
  * 解釈するディレクティブを以下に列挙する（順不同）
    - `listen`
    - `server_name`
    - `error_page`
    - `client_max_body_size`
    - `rewrite or return`
    - `root`
    - `autoindex`
    - `index`
    - ~~`limit_except`~~ 不要かも？
    - `webserv_cgi`
    - `webserv_cgi_pass`
    - `webserv_cgi_param`
* blockの構文(ABNF)
  * http block
    ```
    http_block = [
    *(SP/LF)  "http"                    1*(SP/LF)  "{"  1*(SP/LF)
                       *server_block                    1*(SP/LF)
              "}"                                       1*(SP/LF) ]
    ```
  * server block
    ```
    server_block = [
    "server"                  1*(SP/LF)  "{"  1*(SP/LF)
             *location_block                  1*(SP/LF)
             *directive_line                  1*(SP/LF)
    "}"                                       1*(SP/LF) ]
    ```
  * location block
    ```
    location_block = [
    "location"  1*(SP/LF)  pattern  target   1*(SP/LF)  "{"  1*(SP/LF)
                           *directive_line                   1*(SP/LF)
    "}"                                                      1*(SP/LF) ]
    
    pattern = "=" 1*SP / "^~" 1*SP / ""
    target = URI
    ```
  * directive line
    ```
    directive_line = directive  1*SP  parameters  *SP  ";"
    parameters     = parameter  1*(SP parameter)
    ```
  * Grammar
    - `SP` : ` ` (space)
    - `LF` : `\n`
    - `*` : 0回以上の繰り返し
    - `n*` : n回以上の繰り返し
    - `"string"` : string
    - `directive` : ディレクティブ
    - `parameter` : ディレクティブに対応するパラメータ

### 2-4) データの保持
* `configuration class`に各設定値を詰める
* デフォルト値は要チェック
* blockの並列、ネストへ対応する
  * 各block, ディレクティブが配置可能な階層は以下の通り
  * http
    - client_max_body_size
    - server_i
      * listen_i
      * server_name_i
      * error_page_i
      * rewrite_i or return_i
      * autoindex_i
      * client_max_body_size_i
      * root_i
      * index_i
      * location_k
        - client_max_body_size_k
        - root_k
        - index_k
        - webserv_cgi_k
        - webserv_cgi_pass_k
        - webserv_cgi_param_k
  * http blockが複数のserver blockを保持し、各server blockが複数のlocation blockを保持する形式となる
  * blockごとにクラスを定義し、各クラスと階層的に関連づける方法が良さそう（GPTに頼った）
    ```c++
    class HttpConfig {
     public:
        // HTTP関連の設定を保持するメンバ
        std::vector<ServerConfig> servers; // 複数のServerConfigオブジェクトを保持
        // その他のhttpレベルの設定項目
    };
  
    class ServerConfig {
     public:
        // Server関連の設定を保持するメンバ
        std::string listen;
        std::string server_name;
        std::vector<LocationConfig> locations; // 複数のLocationConfigオブジェクトを保持
        // その他のserverレベルの設定項目
    };
  
    class LocationConfig {
     public:
        // Location関連の設定を保持するメンバ
        std::string path;
        std::string root;
        // その他のlocationレベルの設定項目
    };
  
    class EventConfig {
        // Event関連の設定を保持するメンバ
        // 例: worker_connections など
    };
    ```
  * 各設定項目の保持は、それぞれのクラス内にメンバ変数として定義する
    ```c++ 
    class ServerConfig {
     public:
        std::string listen;
        std::string server_name;
        std::string error_page;
        int client_max_body_size;
        // その他の設定項目
        // ...
    };
    ```

### 2-5) 実装の流れ
* file open
  * path, 拡張子, 権限関係を検証しopen
  * 不正なファイルの場合にエラー
  * データは一時的に保持しfile close or 1行ずつparseし、parse完了後にclose
* parse
  * SP, NF, Symbol(`;`,`{`,etc)で区切る
* tokenize
  * tokenを解釈
  * 解釈不能な記号などがあればエラー？
* 各設定値の読み取り
  * 抽象構文木で構造化
    * 階層深くないが構文木を使えばシンプルにまとまりそう＆設定の追加変更なども容易
  * 構造化不可な箇所があればエラー
* 各設定値の検証
  * 構文エラーの検証


### 2-6) テストの方法
* 関数単位
  - パース関数ごとにテストを記述し、堅牢性、変更容易性を高める
* クラス単位
  - `*.conf`をパースし、得られた各設定値の整合性チェック
  - 不正なファイルや設定値、構文などのエラー判定
* プログラム単位
  - `./webserv -t`: nginxと同様に、`*.conf`の構文チェックoption`-t`を実装し、
    - 構文OK/NGを評価
    - `nginx -t`の結果との比較による整合性評価

