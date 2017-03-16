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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netcfgd.h"

void
netcfgd_delete_v4address(struct imsg *imsg)
{
	char				 ifname[IF_NAMESIZE];
	struct ifaliasreq		 ifaliasreq;
	struct imsg_delete_v4address	 dv4;
	struct sockaddr_in		*in;

	memcpy(&dv4, imsg->data, sizeof(dv4));
	memset(&ifaliasreq, 0, sizeof(ifaliasreq));

	if (if_indextoname(dv4.index, ifname) == NULL) {
		log_warnx("invalid interface index %d", dv4.index);
		return;
	}
	strncpy(ifaliasreq.ifra_name, ifname, sizeof(ifaliasreq.ifra_name));

	in = (struct sockaddr_in *)&ifaliasreq.ifra_addr;
	memcpy(in, &dv4.addr, sizeof(*in));

	if (ioctl(kr_state.inet_fd, SIOCDIFADDR, &ifaliasreq) == -1)
		log_warn("netcfgd_delete_v4address %s",
		    inet_ntoa(in->sin_addr));
}

void
netcfgd_add_v4address(struct imsg *imsg)
{
	char				 ifname[IF_NAMESIZE];
	struct ifaliasreq		 ifaliasreq;
	struct imsg_add_v4address	 av4;
	struct sockaddr_in		*in;

	memcpy(&av4, imsg->data, sizeof(av4));
	memset(&ifaliasreq, 0, sizeof(ifaliasreq));

	if (if_indextoname(av4.index, ifname) == NULL) {
		log_warnx("invalid interface index %d", av4.index);
		return;
	}
	strncpy(ifaliasreq.ifra_name, ifname, sizeof(ifaliasreq.ifra_name));

	/*
	 * Add address & netmask. No need to set broadcast
	 * address. Kernel can figure it out.
	 */
	in = (struct sockaddr_in *)&ifaliasreq.ifra_addr;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(ifaliasreq.ifra_addr);
	in->sin_addr.s_addr = av4.addr.s_addr;

	in = (struct sockaddr_in *)&ifaliasreq.ifra_mask;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(ifaliasreq.ifra_mask);
	in->sin_addr.s_addr = av4.netmask.s_addr;

	if (ioctl(kr_state.inet_fd, SIOCAIFADDR, &ifaliasreq) == -1)
		log_warn("netcfgd_add_v4address %s", inet_ntoa(av4.addr));
}

void
netcfgd_delete_v4route(struct imsg *imsg)
{
	static int			seqno;
	struct rt_msghdr		rtm;
	struct imsg_delete_v4route	dv4;
	struct sockaddr_in		dest, gateway, netmask;
	struct iovec			iov[4];
	int				iovcnt = 0;

	memcpy(&dv4, imsg->data, sizeof(dv4));
	memset(&rtm, 0, sizeof(rtm));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_DELETE;
	rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rtm.rtm_seq = seqno++;
	rtm.rtm_msglen = sizeof(rtm);

	rtm.rtm_index = dv4.index;
	rtm.rtm_tableid = dv4.rdomain;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt++].iov_len = sizeof(rtm);

	memset(&dest, 0, sizeof(dest));
	dest.sin_len = sizeof(dest);
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dv4.dest.s_addr;
	iov[iovcnt].iov_base = &dest;
	iov[iovcnt++].iov_len = sizeof(dest);
	rtm.rtm_msglen += sizeof(dest);

	memset(&gateway, 0, sizeof(gateway));
	gateway.sin_len = sizeof(gateway);
	gateway.sin_family = AF_INET;
	gateway.sin_addr.s_addr = dv4.gateway.s_addr;
	iov[iovcnt].iov_base = &gateway;
	iov[iovcnt++].iov_len = sizeof(gateway);
	rtm.rtm_msglen += sizeof(gateway);

	memset(&netmask, 0, sizeof(netmask));
	netmask.sin_len = sizeof(netmask);
	netmask.sin_family = AF_INET;
	netmask.sin_addr.s_addr = dv4.netmask.s_addr;
	iov[iovcnt].iov_base = &netmask;
	iov[iovcnt++].iov_len = sizeof(netmask);
	rtm.rtm_msglen += sizeof(netmask);

	if (writev(kr_state.route_fd, iov, iovcnt) == -1)
		log_warn("netcfgd_delete_v4route");
}

void
netcfgd_add_v4route(struct imsg *imsg)
{
	struct rt_msghdr rtm;
	struct sockaddr_in dest, gateway, netmask, ifa;
	struct imsg_add_v4route av4;
	struct iovec iov[5];
	int iovcnt = 0;

	/* Build RTM header */

	memset(&rtm, 0, sizeof(rtm));
	memset(&dest, 0, sizeof(dest));
	memset(&netmask, 0, sizeof(netmask));
	memset(&gateway, 0, sizeof(gateway));

	memcpy(&av4, imsg->data, sizeof(av4));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_ADD;
	rtm.rtm_priority = RTP_NONE;
	rtm.rtm_msglen = sizeof(rtm);

	rtm.rtm_tableid = av4.rdomain;
	rtm.rtm_addrs = av4.addrs;
	rtm.rtm_flags = av4.flags;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt++].iov_len = sizeof(rtm);

	if ((av4.addrs & RTA_DST) != 0) {
		dest.sin_len = sizeof(dest);
		dest.sin_family = AF_INET;
		dest.sin_addr.s_addr = av4.dest.s_addr;
		iov[iovcnt].iov_base = &dest;
		iov[iovcnt++].iov_len = sizeof(dest);
		rtm.rtm_msglen += sizeof(dest);
	}

	if ((av4.addrs & RTA_GATEWAY) != 0) {
		gateway.sin_len = sizeof(gateway);
		gateway.sin_family = AF_INET;
		gateway.sin_addr.s_addr = av4.gateway.s_addr;
		iov[iovcnt].iov_base = &gateway;
		iov[iovcnt++].iov_len = sizeof(gateway);
		rtm.rtm_msglen += sizeof(gateway);
	}

	if ((av4.addrs & RTA_NETMASK) != 0) {
		netmask.sin_len = sizeof(netmask);
		netmask.sin_family = AF_INET;
		netmask.sin_addr.s_addr = av4.netmask.s_addr;
		iov[iovcnt].iov_base = &netmask;
		iov[iovcnt++].iov_len = sizeof(netmask);
		rtm.rtm_msglen += sizeof(netmask);
	}

	if ((av4.addrs & RTA_IFA) != 0) {
		ifa.sin_len = sizeof(ifa);
		ifa.sin_family = AF_INET;
		ifa.sin_addr.s_addr = av4.ifa.s_addr;
		iov[iovcnt].iov_base = &ifa;
		iov[iovcnt++].iov_len = sizeof(ifa);
		rtm.rtm_msglen += sizeof(ifa);
	}

	if (writev(kr_state.route_fd, iov, iovcnt) == -1)
		log_warn("netcfgd_add_v4route");
}
