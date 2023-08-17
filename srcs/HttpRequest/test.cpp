# include <string>
# include <map>
# include <unistd.h>

# include <sys/param.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/wait.h>

# include <arpa/inet.h>
# include <netinet/in.h>
# include <netdb.h>

# include <fcntl.h>

#include "../includes/HandlingString.hpp"
#include "../includes/Requestvalue_set.hpp"
#include "../includes/HttpRequest.hpp"

int main()
{
	std::string request = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";

	HttpRequest test(request);
	test.show_requestinfs();
}