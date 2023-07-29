### 複数の空白（空白　たぶ）を許容する 空白位置は準拠 locationディレクティブ外  
* ssl通信に関しては無視する  
* proxyは不対応  
* aioは不対応（課題要件に反してしまうため  
*   
  
## server内   
* listen \[数字\]  
* servername \[("or')名前("or')\] \[("or')名前("or')\]  
複数あることを許容する必要がある  
* root \[nanka]  
* index [codeA codeB codeC ...]   
* allow_methods [methodA methodB ...]  
* error_page [pageA pageB pageC ...] 対象のページのURI  
* chunked_transfer_encoding [on off];  
* access_log \[nanka];  
* error_log \[nanka];  
* keepalive_requests \[数字のみ];一度の接続で受け付けることのできるリクエスト数の上限   
* server_tokens 1;バージョン番号の表示?  
こっちが決めたものを指定して良いから1にしたい  
* autoindex [on or off];  
* rewrite before_url after_url; どうやら正規表現込みのパスを解釈して後ろに回すらしい??  
追記:rewriteは正規表現を扱うもののようなので、これは扱わなくて良い  
https://www.skyarch.net/blog/nginxのrewriteを使ったリダイレクト/  
* return コード番号 URL or text or なし;  
気をつけないといけないのはコード番号のみが必須なのでそれ以外はオプションであるということ  
テクストがよくわからん  
* client_body_buffer_size 8k;数字でも単位でも可能な模様、種類に関して要検討 デフォは8kか16k  
* client_body_timeout 60s;数字でも単位でも可能な模様 デフォルトは60s  
* client_header_buffer_size 1k;同上 デフォルトは1k  
* client_header_timeout 60s;同上 デフォルトは60s  
単位なし s  
ms 1/1000(s)  

* client_max_body_size 1m;同上 デフォルトは1m  
単位で許容されているものは  
バイト（Bytes）  
キロバイト k K (1000倍すればバイト)  
メガバイト m M (2の20乗（2^20）バイト)  
メガバイト g G (1 GB = 2^30 バイト)  
   
* default_type mime-type;mimetypeに関しては調査必要  
  
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
  
めんどくさいからダブルクオーテーションは特殊文字として解釈したくない（願望） 