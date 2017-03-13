/*	$OpenBSD$	*/

/*
 * Copyright 2017 Kenneth R Westerback <krw@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/limits.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <log.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netcfgd.h"
#include "engine.h"

void
engine_delete_v4routes(struct imsg_v4proposal *v4proposal)
{
	struct imsg_delete_v4route	dv4;
	int				bits;
	unsigned int			i, bytes;

	i = 0;
	while (i < v4proposal->rtstatic_len) {
		bits = v4proposal->rtstatic[i++];
		bytes = (bits + 7) / 8;

		if (bytes > sizeof(dv4.netmask))
			return;
		else if (i + bytes > v4proposal->rtstatic_len)
			return;

		memset(&dv4, 0, sizeof(dv4));
		if (bits)
			dv4.netmask.s_addr = htonl(0xffffffff << (32 - bits));
		else
			dv4.netmask.s_addr = INADDR_ANY;

		memcpy(&dv4.dest.s_addr, &v4proposal->rtstatic[i], bytes);
		dv4.dest.s_addr = dv4.dest.s_addr & dv4.netmask.s_addr;
		i += bytes;

		memcpy(&dv4.gateway.s_addr, &v4proposal->rtstatic[i],
		    sizeof(dv4.gateway.s_addr));
		i += sizeof(dv4.gateway.s_addr);

		dv4.index = v4proposal->index;
		dv4.rdomain = v4proposal->rdomain;

		engine_imsg_compose_main(IMSG_DELETE_V4ROUTE, 0, &dv4,
		    sizeof(struct imsg_delete_v4route));
	}
}

void
engine_add_v4routes(struct imsg_v4proposal *v4proposal)
{
	struct imsg_add_v4route	av4;
	int			bits;
	unsigned int		i, bytes;

	i = 0;
	while (i < v4proposal->rtstatic_len) {
		bits = v4proposal->rtstatic[i++];
		bytes = (bits + 7) / 8;

		if (bytes > sizeof(av4.netmask))
			return;
		else if (i + bytes > v4proposal->rtstatic_len)
			return;

		memset(&av4, 0, sizeof(av4));
		if (bits)
			av4.netmask.s_addr = htonl(0xffffffff <<
			    (32 - bits));
		else
			av4.netmask.s_addr = INADDR_ANY;

		memcpy(&av4.dest.s_addr,
		    &v4proposal->rtstatic[i], bytes);
		av4.dest.s_addr = av4.dest.s_addr &
		    av4.netmask.s_addr;
		i += bytes;

		memcpy(&av4.gateway.s_addr, &v4proposal->rtstatic[i],
		    sizeof(av4.gateway.s_addr));
		i += sizeof(av4.gateway.s_addr);

		av4.index = v4proposal->index;
		av4.rdomain = v4proposal->rdomain;

		if (av4.netmask.s_addr == INADDR_ANY &&
		    av4.gateway.s_addr == v4proposal->ifa.s_addr) {
			/*
			 * netmask == INADDR_ANY means it's a default route.
			 *
			 * ifa == gateway address means we want the equivalent
			 * of
			 *	route <rdomain> add default -iface <gateway>
			 */
			av4.addrs = RTA_DST | RTA_NETMASK;
			av4.flags = 0;
		} else if (av4.netmask.s_addr == INADDR_ANY) {
			/*
			 * netmask == INADDR_ANY means it's a default route.
			 *
			 * We want the eqivalent of
			 *
			 *	route <rdomain> add default <gateway>
			 */
			av4.addrs = RTA_DST | RTA_NETMASK | RTA_GATEWAY;
			av4.flags = RTF_GATEWAY | RTF_STATIC;
		} else if (av4.netmask.s_addr == INADDR_BROADCAST) {
			/*
			 * netmask == INADDR_BROADCAST means we were given
			 * a /32 IP assignment. To make sure the gateway
			 * address is routable we want the equivalent of
			 *
			 *     route add -net <gateway> \
			 *         -netmask 255.255.255.255 \
			 *         -cloning -iface <ifa>
			 */
			av4.addrs= RTA_DST | RTA_NETMASK | RTA_GATEWAY;
			av4.flags = RTF_CLONING | RTF_STATIC;
			av4.dest.s_addr = av4.gateway.s_addr;
			av4.gateway.s_addr = v4proposal->ifa.s_addr;
		} else {
			/*
			 * Any other netmask value means a 'normal' static
			 * route.
			 */
			av4.addrs= RTA_DST | RTA_NETMASK | RTA_GATEWAY;
			av4.flags = RTF_GATEWAY | RTF_STATIC;
		}

		engine_imsg_compose_main(IMSG_ADD_V4ROUTE, 0, &av4,
		    sizeof(struct imsg_add_v4route));
	}
}

void
engine_delete_v4address(struct imsg_v4proposal *v4proposal)
{
	struct imsg_delete_v4address	 dv4;
	char				*ifname;

	memset(&dv4, 0, sizeof(dv4));
	memcpy(&dv4.addr, &v4proposal->ifa, sizeof(dv4.addr));

	ifname = if_indextoname(v4proposal->index, dv4.name);
	if (ifname == NULL)
		log_warnx("invalid interface index %d", v4proposal->index);
	else
		engine_imsg_compose_main(IMSG_DELETE_V4ADDRESS, 0, &dv4,
		    sizeof(dv4));
}

void
engine_add_v4address(struct imsg_v4proposal *v4proposal)
{
	struct imsg_add_v4address	 av4;
	char				*ifname;

	memset(&av4, 0, sizeof(av4));

	memcpy(&av4.addr, &v4proposal->ifa, sizeof(av4.addr));
	memcpy(&av4.mask, &v4proposal->netmask, sizeof(av4.mask));

	ifname = if_indextoname(v4proposal->index, av4.name);
	if (ifname == NULL)
		log_warnx("invalid interface index %d", v4proposal->index);
	else
		engine_imsg_compose_main(IMSG_ADD_V4ADDRESS, 0, &av4,
		    sizeof(av4));
}
