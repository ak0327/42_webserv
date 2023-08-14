一旦、ここのテスト形式は外部に情報を依存させないために、こっち側で作った文章をパースする形で作ることにする  
具体的には下記の形を想定している  
  
UserRequestの例  	
  
POST /search.html HTTP/1.1\r\n  
Host: wa3.i-3-i.info\r\n  
Connection: keep-alive\r\n  
Content-Length: 38\r\n  
Cache-Control: max-age=0\r\n  
Origin: http://wa3.i-3-i.info\r\n  
Upgrade-Insecure-Requests: 1\r\n	 						
User-Agent: うんちゃら\r\n  
Content-Type: application/x-www-form-urlencoded\r\n  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n  
Referer: http://wa3.i-3-i.info/index.html\r\n  
Accept-Encoding: gzip, deflate\r\n  
Accept-Language: ja,en-US;q=0.8,en;q=0.6\r\n  
\r\n  
q=test&submitSearch=%E6%A4%9C%E7%B4%A2  
  
もし、他に方法があれば教えて欲しい  
※socketがあれば問題なく行うことができるがただしsocketクラスに依存するためあまりテストとしては良くないのではないかと考えている  