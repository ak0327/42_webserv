#ifndef SOCKET_HPP
#define SOCKET_HPP

# include <iostream>
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

class Socket
{
	private:
		int	_socketFD;
		int _status;

		int			makesocket(std::string const &port);
		int			makeAddressInfo(std::string const &port, struct addrinfo **res);

	public:
		Socket(std::string&);
		Socket(const Socket &other);
		Socket &operator=(const Socket &other);
		~Socket();

		int	get_socketFD(void) const;
		int	get_status(void) const;
};

#endif