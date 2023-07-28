### 複数の空白（空白　たぶ）を許容する 空白位置は準拠 locationディレクティブ外  
* ssl通信に関しては無視する  
* proxyは不対応  
* aioは不対応（課題要件に反してしまうため  
*   
  
## server内   
* listen \[数字\]  
* servername \[("or')名前("or')\]  
* root \[nanka]  
* index [codeA codeB codeC ...]   
* allow_methods [methodA methodB ...]  
* error_page [pageA pageB pageC ...] 対象のページのURI  
* types{A A'smime B B'smime ...} 許容できるmimetypeは後々調べる  
* chunked_transfer_encoding [on off];  
* access_log ;  
* error_log ;  
* keepalive_requests ;一度の接続で受け付けることのできるリクエスト数の上限  
* keepalive_timeout ;キープアライブのタイムアウトまでの秒数  
* server_tokens ;バージョン番号の表示?  
* autoindex [on or off];  
* rewrite before_url after_url; どうやら正規表現込みのパスを解釈して後ろに回すらしい??
* return コード番号 path;  
* client_body_buffer_size 8k;数字でも単位でも可能な模様、種類に関して要検討 デフォは8kか16k  
* client_body_timeout 60s;数字でも単位でも可能な模様 デフォルトは60s  
* client_header_buffer_size 1k;同上 デフォルトは1k  
* client_header_timeout 60s;同上 デフォルトは60s  
* client_max_body_size 1m;同上 デフォルトは1m  
* default_type mime-type;mimetypeに関しては調査必要  
* etag on | off;意味は理解したいかも 可能であれば  
  
## location内  
* access_log ;  
* error_log ;  
* keepalive_requests ;一度の接続で受け付けることのできるリクエスト数の上限  
* keepalive_timeout ;キープアライブのタイムアウトまでの秒数  
* server_tokens ;バージョン番号の表示  
* root \[nanka] ※空白は一つ  
* areas nankaPATH;  
* index [pageA pageB pageC ...]  
* autoindex ;  
* rewrite ; ??  
* client_body_buffer_size 8k;数字でも単位でも可能な模様、種類に関して要検討  
* client_body_timeout 60s;数字でも単位でも可能な模様 デフォルトは60s  
* client_header_buffer_size 1k;同上 デフォルトは1k  
* client_header_timeout 60s;1同上 デフォルトは60s  
* client_max_body_size 1m;同上 デフォルトは1m  
* default_type mime-type;mimetypeに関しては調査必要  
* etag on | off;意味は理解したいかも 可能であれば  
* log_not_found [on off];ファイルが見つからなかった場合のエラーログを出すかどうか決めれる  
  

## 一旦対応しないけど書き込みは可能な設定（使い方わからん。。。）  
connection_pool_size size;単位は許容しないので注意  
directio size | off;単位許容 使い方不明。。。  
directio_alignment size;単位は許容しないので注意  
disable_symlinks off;ファイルを開く時にシンボリックリンクをどう扱うかを決定  
if_modified_since off | exact | before;  
keepalive_requests 1000;使い方不明  
keepalive_time 1h;使い方不明  
large_client_header_buffers 4 8k;  
  
※ 気になっていること  
nginxの数値を設定できる箇所、限界ちってなんだ？一旦INT_MAX(2147483647)にしときたい  
chatGPT曰く  
Nginxのタイムアウト設定や関連する値については、基本的にはINTの範囲（通常は32ビットまたは64ビット）内で指定することが一般的です。これは  
タイムアウト設定が内部的に整数型（通常はintまたはtime_t）で表現されるためです。  
とのこと  
  
めんどくさいからダブルクオーテーションは特殊文字として解釈したくない（願望） 