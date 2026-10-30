// SPDX-License-Identifier: GPL-2.0-only
/* Loopback traffic generator for the disposable VM. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
	fprintf(stderr, "regex_traffic: line %d: %s (errno=%d)\n", \
		__LINE__, #expr, errno); exit(1); \
} } while (0)

static const char match[] = "hello42\0world";
static const char *const payloads[] = { match, "miss", "hello42\0", "world", "" };
static const size_t lengths[] = { sizeof(match) - 1, 4, 8, 5, 0 };

static void transfer(int fd, void *buffer, size_t len, int writing)
{
	char *p = buffer;
	ssize_t count;

	while (len) {
		count = writing ? send(fd, p, len, 0) : recv(fd, p, len, 0);
		CHECK(count > 0);
		p += count;
		len -= count;
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_storage address = {};
	struct timeval timeout = { .tv_sec = 1 };
	socklen_t size;
	int family, tcp, server, client, one = 1, status;
	unsigned int i;
	pid_t child;
	char buffer[128], ack = '.';
	ssize_t count;

	CHECK(argc == 3 || argc == 4);
	CHECK(!strcmp(argv[1], "4") || !strcmp(argv[1], "6"));
	CHECK(!strcmp(argv[2], "tcp") || !strcmp(argv[2], "udp"));
	family = !strcmp(argv[1], "4") ? AF_INET : AF_INET6;
	tcp = !strcmp(argv[2], "tcp");
	CHECK(argc == 3 || (!tcp && (!strcmp(argv[3], "drop") || !strcmp(argv[3], "accept"))));
	alarm(10);
	if (family == AF_INET) {
		struct sockaddr_in *ip = (void *)&address;

		ip->sin_family = family;
		ip->sin_port = htons(49001);
		CHECK(inet_pton(family, "127.0.0.1", &ip->sin_addr) == 1);
		size = sizeof(*ip);
	} else {
		struct sockaddr_in6 *ip = (void *)&address;

		ip->sin6_family = family;
		ip->sin6_port = htons(49001);
		CHECK(inet_pton(family, "::1", &ip->sin6_addr) == 1);
		size = sizeof(*ip);
	}
	server = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	CHECK(server >= 0);
	CHECK(!setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
	CHECK(!bind(server, (void *)&address, size));
	if (tcp) {
		CHECK(!listen(server, 1));
		child = fork();
		CHECK(child >= 0);
		if (!child) {
			client = accept(server, NULL, NULL);
			CHECK(client >= 0);
			for (i = 0; i < 4; i++) {
				transfer(client, buffer, lengths[i], 0);
				CHECK(!memcmp(buffer, payloads[i], lengths[i]));
				transfer(client, &ack, 1, 1);
			}
			close(client);
			close(server);
			_exit(0);
		}
		client = socket(family, SOCK_STREAM, 0);
		CHECK(client >= 0);
		CHECK(!setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
		CHECK(!connect(client, (void *)&address, size));
		for (i = 0; i < 4; i++) {
			transfer(client, (void *)payloads[i], lengths[i], 1);
			transfer(client, buffer, 1, 0);
			CHECK(buffer[0] == ack);
		}
		CHECK(waitpid(child, &status, 0) == child);
		CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
	} else {
		client = socket(family, SOCK_DGRAM, 0);
		CHECK(client >= 0);
		CHECK(!setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
		for (i = 0; i < (argc == 4 ? 2 : 5); i++) {
			int blocked = argc == 4 && (i == 0) == !strcmp(argv[3], "drop");

			count = sendto(client, payloads[i], lengths[i], 0, (void *)&address, size);
			CHECK(count == (ssize_t)lengths[i] || (blocked && count < 0 && errno == EPERM));
			if (blocked)
				continue;
			count = recv(server, buffer, sizeof(buffer), 0);
			CHECK(count == (ssize_t)lengths[i]);
			CHECK(!memcmp(buffer, payloads[i], lengths[i]));
		}
		if (argc == 4) {
			CHECK(recv(server, buffer, sizeof(buffer), 0) < 0);
			CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
		}
	}
	close(client);
	close(server);
	return 0;
}
