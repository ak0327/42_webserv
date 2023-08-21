#include "Socket.hpp"

Socket::Socket(std::string &port)
{
	this->_status = makesocket(port);
}

Socket::Socket(const Socket &other)
{
	this->_status = other._status;
	this->_socketFD = other._socketFD;
}

Socket& Socket::operator=(const Socket &other)
{
	if (this == &other)
		return (*this);
	this->_status = other._status;
	this->_socketFD = other._socketFD;
	return (*this);
}

Socket::~Socket()
{

}

int Socket::makesocket(std::string const &port)
{
	struct addrinfo *addr_inf = NULL;

	if (makeAddressInfo(port, &addr_inf) == -1)
		return (-1);
	_socketFD = socket(addr_inf->ai_family, addr_inf->ai_socktype, addr_inf->ai_protocol);
	if (_socketFD == -1)
	{
		std::cout << "socket func is missed" << std::endl;
		close(_socketFD);
		freeaddrinfo(addr_inf);
	}

	int opt = 1;
	if (setsockopt(_socketFD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		perror("setsockopt");
		close(_socketFD);
		freeaddrinfo(addr_inf);
		return (-1);
	}

	if (bind(_socketFD, addr_inf->ai_addr, addr_inf->ai_addrlen) == -1)
	{
		std::cout << "bind func is missed" << std::endl;
		close(_socketFD);
		freeaddrinfo(addr_inf);
		return (-1);
	}

	if (listen(_socketFD, SOMAXCONN) == -1) {
		perror("listen");
		close(_socketFD);
		freeaddrinfo(addr_inf);
		return (-1);
	}

	fcntl(_socketFD, F_SETFL, O_NONBLOCK);
	freeaddrinfo(addr_inf);
	return (0);
}

int Socket::makeAddressInfo(std::string const &port, struct addrinfo **res)
{
	struct addrinfo	hints;
	int				errcode;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;//TCPとか　ipv4とか
	hints.ai_socktype = SOCK_STREAM;//安定生のある通信
	hints.ai_flags = AI_PASSIVE;//bindするのに最適

	if ((errcode = getaddrinfo(NULL, port.c_str(), &hints, res)) != 0)
	{
		perror("getaddrinfo");
		return (-1);
	}
	return (0);
}

