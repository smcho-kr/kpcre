// SPDX-License-Identifier: GPL-2.0
/* VM-only TCP client/server. An application ACK forces each payload to arrive separately. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *what)
{
	perror(what);
	exit(1);
}

static void transfer(int fd, void *data, size_t length, int sending)
{
	char *cursor = data;
	while (length) {
		ssize_t count = sending ? send(fd, cursor, length, MSG_NOSIGNAL) : recv(fd, cursor, length, 0);
		if (count <= 0)
			fail(sending ? "send" : "recv");
		cursor += count;
		length -= count;
	}
}

static void setup(int fd)
{
	int one = 1;
	struct timeval timeout = { .tv_sec = 5 };
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
		fail("setsockopt");
}

int main(int argc, char **argv)
{
	const char *pairs[] = { "abc", "defghi", "jkl", "xyz" };
	const char *letters[] = { "a", "b", "c", "d", "e", "f", "g", "h", "i" };
	const char **pieces = pairs;
	unsigned int piece_count = sizeof(pairs) / sizeof(*pairs);
	struct sockaddr_storage address = {};
	socklen_t size;
	int family, listener, client, status, one = 1;
	pid_t child;
	unsigned int i;
	char ack = 'k';

	if ((argc != 3 && argc != 4) || (argc == 4 && strcmp(argv[3], "letters"))) {
		fprintf(stderr, "usage: %s 4|6 port [letters]\n", argv[0]);
		return 2;
	}
	if (argc == 4) {
		pieces = letters;
		piece_count = sizeof(letters) / sizeof(*letters);
	}
	family = !strcmp(argv[1], "6") ? AF_INET6 : AF_INET;
	address.ss_family = family;
	if (family == AF_INET6) {
		struct sockaddr_in6 *in = (void *)&address;
		in->sin6_port = htons(atoi(argv[2]));
		in->sin6_addr = in6addr_loopback;
		size = sizeof(*in);
	} else {
		struct sockaddr_in *in = (void *)&address;
		in->sin_port = htons(atoi(argv[2]));
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		size = sizeof(*in);
	}
	listener = socket(family, SOCK_STREAM, 0);
	if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
	    bind(listener, (void *)&address, size) || listen(listener, 1))
		fail("listen");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		char received[16];
		int fd = accept(listener, NULL, NULL);
		if (fd < 0)
			fail("accept");
		setup(fd);
		for (i = 0; i < piece_count; i++) {
			transfer(fd, received, strlen(pieces[i]), 0);
			if (memcmp(received, pieces[i], strlen(pieces[i])))
				_exit(1);
			transfer(fd, &ack, 1, 1);
		}
		close(fd);
		close(listener);
		_exit(0);
	}
	close(listener);
	client = socket(family, SOCK_STREAM, 0);
	if (client < 0)
		fail("socket");
	setup(client);
	if (connect(client, (void *)&address, size))
		fail("connect");
	for (i = 0; i < piece_count; i++) {
		transfer(client, (void *)pieces[i], strlen(pieces[i]), 1);
		transfer(client, &ack, 1, 0);
	}
	close(client);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return 1;
	puts("ids_traffic: PASS");
	return 0;
}
