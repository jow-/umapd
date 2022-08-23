/*
 * Copyright (c) 2022 Jo-Philipp Wich <jo@mein.io>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "ucode/module.h"

#ifndef ETH_P_1905
#define ETH_P_1905 0x893a
#endif

#define err_return(err, ...) do { set_error(err, __VA_ARGS__); return NULL; } while(0)

static struct {
	int code;
	char *msg;
} last_error;

static uc_resource_type_t *sock_type;

typedef struct {
	int sock;
	unsigned ifidx;
} u1905_socket_t;

__attribute__((format(printf, 2, 3))) static void
set_error(int errcode, const char *fmt, ...)
{
	va_list ap;

	free(last_error.msg);

	last_error.code = errcode;
	last_error.msg = NULL;

	if (fmt) {
		va_start(ap, fmt);
		xvasprintf(&last_error.msg, fmt, ap);
		va_end(ap);
	}
}

static uc_value_t *
u1905_error(uc_vm_t *vm, size_t nargs)
{
	uc_stringbuf_t *buf;
	const char *s;

	if (last_error.code == 0)
		return NULL;

	buf = ucv_stringbuf_new();

	if (last_error.code == 0 && last_error.msg) {
		ucv_stringbuf_addstr(buf, last_error.msg, strlen(last_error.msg));
	}
	else {
		s = strerror(last_error.code);

		ucv_stringbuf_addstr(buf, s, strlen(s));

		if (last_error.msg)
			ucv_stringbuf_printf(buf, ": %s", last_error.msg);
	}

	set_error(0, NULL);

	return ucv_stringbuf_finish(buf);
}

static uc_value_t *
u1905_socket_fileno(uc_vm_t *vm, size_t nargs)
{
	u1905_socket_t **sk = uc_fn_this("u1905.socket");

	if (!sk || !*sk || (*sk)->sock == -1)
		err_return(EBADF, NULL);

	return ucv_int64_new((*sk)->sock);
}

static uc_value_t *
u1905_socket_send(uc_vm_t *vm, size_t nargs)
{
	u1905_socket_t **sk = uc_fn_this("u1905.socket");
	uc_value_t *dstmac = uc_fn_arg(0);
	uc_value_t *buffer = uc_fn_arg(1);
	struct sockaddr_ll sa = { 0 };
	struct ether_addr *dst;
	ssize_t wlen;

	if (!sk || !*sk || (*sk)->sock == -1)
		err_return(EBADF, NULL);

	if (ucv_type(dstmac) != UC_STRING ||
		(dst = ether_aton(ucv_string_get(dstmac))) == NULL)
		err_return(EINVAL, "Invalid destination MAC address");

	if (ucv_type(buffer) != UC_STRING)
		err_return(EINVAL, "Invalid packet data argument");

	sa.sll_ifindex = (*sk)->ifidx;
	sa.sll_halen = ETH_ALEN;
	memcpy(sa.sll_addr, dst->ether_addr_octet, ETH_ALEN);

	wlen = sendto((*sk)->sock,
	              ucv_string_get(buffer), ucv_string_length(buffer),
	              0, (struct sockaddr *)&sa, sizeof(sa));

	if (wlen == -1)
		err_return(errno, "Failed to send buffer contents");

	return ucv_int64_new(wlen);
}

static uc_value_t *
u1905_socket_recv(uc_vm_t *vm, size_t nargs)
{
	u1905_socket_t **sk = uc_fn_this("u1905.socket");
	uc_stringbuf_t *buf;
	ssize_t blen, rlen;

	if (!sk || !*sk || (*sk)->sock == -1)
		err_return(EBADF, NULL);

	buf = ucv_stringbuf_new();
	blen = printbuf_length(buf);
	printbuf_memset(buf, blen + 1518 - 1, 0, 1);
	buf->bpos = blen;

	rlen = recvfrom((*sk)->sock, buf->buf + buf->bpos, 1518, 0, NULL, NULL);

	if (rlen == -1) {
		printbuf_free(buf);
		err_return(errno, "Failed to receive buffer contents");
	}

	buf->bpos += rlen;

	return ucv_stringbuf_finish(buf);
}

static uc_value_t *
u1905_socket_close(uc_vm_t *vm, size_t nargs)
{
	u1905_socket_t **sk = uc_fn_this("u1905.socket");

	if (!sk || !*sk || (*sk)->sock == -1)
		err_return(EBADF, NULL);

	close((*sk)->sock);
	(*sk)->sock = -1;

	return ucv_boolean_new(true);
}

static uc_value_t *
u1905_socket(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ifname = uc_fn_arg(0);
	uc_value_t *proto = uc_fn_arg(1);
	struct sockaddr_ll sa = { 0 };
	struct packet_mreq mr = { 0 };
	int sock = -1, flags, pr = 0;
	u1905_socket_t *sk;
	unsigned ifidx;


	if (ucv_type(ifname) != UC_STRING)
		err_return(EINVAL, "Invalid ifname argument");

	if (proto) {
		if (ucv_type(proto) != UC_INTEGER)
			err_return(EINVAL, "Invalid protocol argument");

		pr = (int)ucv_int64_get(proto);
	}

	sock = socket(AF_PACKET, SOCK_RAW, htons(pr));

	if (sock == -1)
		err_return(errno, "Unable to create raw packet socket");

	flags = fcntl(sock, F_GETFL, 0);

	if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		close(sock);
		err_return(errno, "Unable to set socket flags");
	}

	flags = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) == -1) {
		close(sock);
		err_return(errno, "Unable to set SO_REUSEADDR socket option");
	}

	ifidx = if_nametoindex(ucv_string_get(ifname));

	if (ifidx == 0) {
		close(sock);
		err_return(errno, "Unable to resolve interface index");
	}

	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(pr);
	sa.sll_halen = ETH_ALEN;
	sa.sll_ifindex = ifidx;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		close(sock);
		err_return(errno, "Unable to bind packet socket");
	}

	if (pr == ETH_P_1905 || pr == ETH_P_LLDP) {
		mr.mr_type = PACKET_MR_MULTICAST;
		mr.mr_alen = ETH_ALEN;
		mr.mr_ifindex = ifidx;

		memcpy(mr.mr_address,
		       (pr == ETH_P_LLDP) ? "\x01\x80\xC2\x00\x00\x0E" : "\x01\x80\xC2\x00\x00\x13",
		       ETH_ALEN);

		if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
			close(sock);
			err_return(errno, "Unable to add socket multicast membership");
		}

		mr.mr_type = PACKET_MR_PROMISC;
		mr.mr_ifindex = ifidx;
		mr.mr_alen = 0;
		memset(mr.mr_address, 0, sizeof(mr.mr_address));

		if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
			close(sock);
			err_return(errno, "Unable to enable promiscious mode");
		}
	}

	sk = xalloc(sizeof(*sk));
	sk->sock = sock;
	sk->ifidx = ifidx;

	return uc_resource_new(sock_type, sk);
}

static const uc_function_list_t sock_fns[] = {
	{ "fileno",	u1905_socket_fileno },
	{ "send",	u1905_socket_send },
	{ "recv",	u1905_socket_recv },
	{ "close",	u1905_socket_close },
};

static const uc_function_list_t u1905_fns[] = {
	{ "error",	u1905_error },
	{ "socket",	u1905_socket },
};

static void free_sock(void *ud) {
	u1905_socket_t *sk = ud;

	close(sk->sock);
	free(sk);
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, u1905_fns);

	sock_type = uc_type_declare(vm, "u1905.socket", sock_fns, free_sock);
}
