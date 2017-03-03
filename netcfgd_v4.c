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

void	v4_flush_routes(struct imsg_v4proposal *);
void	v4_add_routes(struct imsg_v4proposal *);
void	v4_add_direct_route(int, struct in_addr, struct in_addr, struct in_addr);
void	v4_add_route(int, struct in_addr, struct in_addr, struct in_addr,
	    struct in_addr, int, int);
void	v4_resolv_conf_contents(struct imsg_v4proposal *v4proposal);

void	v4_delete_route(struct rt_msghdr *);
int	v4_check_route_label(struct sockaddr_rtlabel *);

#define	ROUTE_LABEL_NONE		1
#define	ROUTE_LABEL_NOT_NETCFGD		2
#define	ROUTE_LABEL_NETCFGD_OURS	3
#define	ROUTE_LABEL_NETCFGD_UNKNOWN	4
#define	ROUTE_LABEL_NETCFGD_LIVE	5
#define	ROUTE_LABEL_NETCFGD_DEAD	6

void
v4_execute_proposal(struct imsg *imsg)
{
	struct imsg_v4proposal v4proposal;
	struct ifaliasreq ifaliasreq;
	struct ifreq ifr;
	char name[IF_NAMESIZE];
	struct in_addr addr;
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *in;

	memcpy(&v4proposal, imsg->data, sizeof(v4proposal));
	if (if_indextoname(v4proposal.index, name) == NULL)
		fatal("if_indextoname(%d) failed", v4proposal.index);

	/* 1) Delete current addresses. */

	if (getifaddrs(&ifap) != 0)
		fatal("delete_addresses getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_LOOPBACK) ||
		    (ifa->ifa_flags & IFF_POINTOPOINT) ||
		    (!(ifa->ifa_flags & IFF_UP)) ||
		    (ifa->ifa_addr->sa_family != AF_INET) ||
		    (strcmp(name, ifa->ifa_name) != 0))
			continue;

		memcpy(&addr, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
		    sizeof(addr));

		memset(&ifaliasreq, 0, sizeof(ifaliasreq));
		strncpy(ifaliasreq.ifra_name, name,
		    sizeof(ifaliasreq.ifra_name));

		in = (struct sockaddr_in *)&ifaliasreq.ifra_addr;
		in->sin_family = AF_INET;
		in->sin_len = sizeof(ifaliasreq.ifra_addr);
		in->sin_addr.s_addr = addr.s_addr;

		if (ioctl(kr_state.inet_fd, SIOCDIFADDR, &ifaliasreq) == -1) {
			if (errno != EADDRNOTAVAIL)
				log_warn("SIOCDIFADDR failed (%s)",
				    inet_ntoa(addr));
		}

	}

	freeifaddrs(ifap);

	/* 2) Flush routes. */
	v4_flush_routes(&v4proposal);

	/* 3) Set MTU. */
	if (((v4proposal.inits & RTV_MTU) != 0) && v4proposal.mtu != 0) {
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		ifr.ifr_mtu = v4proposal.mtu;
		if (ioctl(kr_state.inet_fd, SIOCSIFMTU, &ifr) == -1)
			log_warn("SIOCSIFMTU failed (%d)", v4proposal.mtu);
	}

	/*
	 * 4) Add address & netmask. No need to set broadcast
	 *    address. Kernel can figure it out.
	 */
	memset(&ifaliasreq, 0, sizeof(ifaliasreq));
	strncpy(ifaliasreq.ifra_name, name, sizeof(ifaliasreq.ifra_name));

	in = (struct sockaddr_in *)&ifaliasreq.ifra_addr;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(ifaliasreq.ifra_addr);
	in->sin_addr.s_addr = v4proposal.ifa.s_addr;

	in = (struct sockaddr_in *)&ifaliasreq.ifra_mask;
	in->sin_family = AF_INET;
	in->sin_len = sizeof(ifaliasreq.ifra_mask);
	in->sin_addr.s_addr = v4proposal.netmask.s_addr;

	if (ioctl(kr_state.inet_fd, SIOCAIFADDR, &ifaliasreq) == -1)
		log_warn("SIOCAIFADDR failed (%s)", inet_ntoa(addr));

	/* 5) Add static routes (including default route.). */
	if ((v4proposal.addrs & RTA_STATIC) != 0)
		v4_add_routes(&v4proposal);

	/* 6) Update resolv.conf. */
	if ((v4proposal.addrs & (RTA_SEARCH | RTA_DNS)) != 0)
		v4_resolv_conf_contents(&v4proposal);
}

void
v4_flush_routes(struct imsg_v4proposal *v4proposal)
{
	struct sockaddr *rti_info[RTAX_MAX];
	int mib[7];
	size_t needed;
	char *lim, *buf = NULL, *bufp, *next, *errmsg = NULL;
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	struct sockaddr_in *sa_in;
	struct sockaddr_rtlabel *sa_rl;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_GATEWAY;
	mib[6] = v4proposal->rdomain;

	while (1) {
		if (sysctl(mib, 7, NULL, &needed, NULL, 0) == -1) {
			errmsg = "sysctl size of routes:";
			break;
		}
		if (needed == 0) {
			free(buf);
			return;
		}
		if ((bufp = realloc(buf, needed)) == NULL) {
			errmsg = "routes buf realloc:";
			break;
		}
		buf = bufp;
		if (sysctl(mib, 7, buf, &needed, NULL, 0) == -1) {
			if (errno == ENOMEM)
				continue;
			errmsg = "sysctl retrieval of routes:";
			break;
		}
		break;
	}

	if (errmsg) {
		log_warn("route cleanup failed - %s (msize=%zu)", errmsg,
		    needed);
		free(buf);
		return;
	}

	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
		kr_get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

		sa_rl = (struct sockaddr_rtlabel *)rti_info[RTAX_LABEL];
		sa_in = (struct sockaddr_in *)rti_info[RTAX_NETMASK];

		switch (v4_check_route_label(sa_rl)) {
		case ROUTE_LABEL_NETCFGD_OURS:
		case ROUTE_LABEL_NETCFGD_DEAD:
			/*
			 * Always delete routes we labeled and labels from
			 * processes that do not exist.
			 */
			v4_delete_route(rtm);
			break;
		case ROUTE_LABEL_NETCFGD_LIVE:
		case ROUTE_LABEL_NETCFGD_UNKNOWN:
			/* Another(?) netcfgd's responsibility. */
			break;
		case ROUTE_LABEL_NONE:
		case ROUTE_LABEL_NOT_NETCFGD:
			/* Delete default routes on our interface. */
			if (rtm->rtm_index == v4proposal->index &&
			    sa_in &&
			    sa_in->sin_addr.s_addr == INADDR_ANY &&
			    rtm->rtm_tableid == v4proposal->rdomain)
				v4_delete_route(rtm);
			break;
		default:
			break;
		}
	}

	free(buf);
}

void
v4_delete_route(struct rt_msghdr *rtm)
{
	static int seqno;
	ssize_t rlen;

	rtm->rtm_type = RTM_DELETE;
	rtm->rtm_seq = seqno++;

	rlen = write(kr_state.route_fd, (char *)rtm, rtm->rtm_msglen);
	if (rlen == -1) {
		if (errno != ESRCH)
			fatal("RTM_DELETE write");
	} else if (rlen < (int)rtm->rtm_msglen)
		fatalx("short RTM_DELETE write (%zd)\n", rlen);
}

int
v4_check_route_label(struct sockaddr_rtlabel *label)
{
	pid_t pid;

	if (!label)
		return (ROUTE_LABEL_NONE);

	if (strncmp("NETCFGD ", label->sr_label, 9) != 0)
		return (ROUTE_LABEL_NOT_NETCFGD);

	pid = (pid_t)strtonum(label->sr_label + 9, 1, INT_MAX, NULL);
	if (pid <= 0)
		return (ROUTE_LABEL_NETCFGD_UNKNOWN);

	if (pid == getpid())
		return (ROUTE_LABEL_NETCFGD_OURS);

	if (kill(pid, 0) == -1) {
		if (errno == ESRCH)
			return (ROUTE_LABEL_NETCFGD_DEAD);
		else
			return (ROUTE_LABEL_NETCFGD_UNKNOWN);
	}

	return (ROUTE_LABEL_NETCFGD_LIVE);
}


void
v4_add_route(int rdomain, struct in_addr dest_addr, struct in_addr mask_addr,
    struct in_addr gateway_addr, struct in_addr ifa_addr, int addrs,
    int flags)
{
	struct rt_msghdr	rtm;
	struct sockaddr_in	dest, gateway, mask, ifa;
	struct sockaddr_rtlabel label;
	struct iovec		iov[6];
	int			iovcnt = 0;

	/* Build RTM header */

	memset(&rtm, 0, sizeof(rtm));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_ADD;
	rtm.rtm_tableid = rdomain;
	rtm.rtm_priority = RTP_NONE;
	rtm.rtm_msglen = sizeof(rtm);
	rtm.rtm_addrs = addrs;
	rtm.rtm_flags = flags;

	iov[iovcnt].iov_base = &rtm;
	iov[iovcnt++].iov_len = sizeof(rtm);

	if (addrs & RTA_DST) {
		memset(&dest, 0, sizeof(dest));

		dest.sin_len = sizeof(dest);
		dest.sin_family = AF_INET;
		dest.sin_addr.s_addr = dest_addr.s_addr;

		rtm.rtm_msglen += sizeof(dest);

		iov[iovcnt].iov_base = &dest;
		iov[iovcnt++].iov_len = sizeof(dest);
	}

	if (addrs & RTA_GATEWAY) {
		memset(&gateway, 0, sizeof(gateway));

		gateway.sin_len = sizeof(gateway);
		gateway.sin_family = AF_INET;
		gateway.sin_addr.s_addr = gateway_addr.s_addr;

		rtm.rtm_msglen += sizeof(gateway);

		iov[iovcnt].iov_base = &gateway;
		iov[iovcnt++].iov_len = sizeof(gateway);
	}

	if (addrs & RTA_NETMASK) {
		memset(&mask, 0, sizeof(mask));

		mask.sin_len = sizeof(mask);
		mask.sin_family = AF_INET;
		mask.sin_addr.s_addr = mask_addr.s_addr;

		rtm.rtm_msglen += sizeof(mask);

		iov[iovcnt].iov_base = &mask;
		iov[iovcnt++].iov_len = sizeof(mask);
	}

	if (addrs & RTA_IFA) {
		memset(&ifa, 0, sizeof(ifa));

		ifa.sin_len = sizeof(ifa);
		ifa.sin_family = AF_INET;
		ifa.sin_addr.s_addr = ifa_addr.s_addr;

		rtm.rtm_msglen += sizeof(ifa);

		iov[iovcnt].iov_base = &ifa;
		iov[iovcnt++].iov_len = sizeof(ifa);
	}

	/* Add our label so we can identify the route as our creation. */
	memset(&label, 0, sizeof(label));
	label.sr_len = sizeof(label);
	label.sr_family = AF_UNSPEC;
	snprintf(label.sr_label, sizeof(label.sr_label), "NETCFGD %d",
	    (int)getpid());

	rtm.rtm_addrs |= RTA_LABEL;
	rtm.rtm_msglen += sizeof(label);
	iov[iovcnt].iov_base = &label;
	iov[iovcnt++].iov_len = sizeof(label);

	if (writev(kr_state.route_fd, iov, iovcnt) == -1)
		log_warn("v4_add_route");
}

void
v4_add_direct_route(int rdomain, struct in_addr dest, struct in_addr mask,
    struct in_addr iface)
{
	struct in_addr ifa = { INADDR_ANY };

	v4_add_route(rdomain, dest, mask, iface, ifa,
	    RTA_DST | RTA_NETMASK | RTA_GATEWAY, RTF_CLONING | RTF_STATIC);
}

void
v4_add_routes(struct imsg_v4proposal *v4proposal)
{
	struct in_addr	 dest, netmask, gateway, iface;
	int		 bits;
	unsigned int	 i, bytes;

	memcpy(&iface.s_addr, &v4proposal->ifa, sizeof(iface));

	i = 0;
	while (i < v4proposal->rtstatic_len) {
		bits = v4proposal->rtstatic[i++];
		bytes = (bits + 7) / 8;

		if (bytes > sizeof(netmask))
			return;
		else if (i + bytes > v4proposal->rtstatic_len)
			return;

		if (bits)
			netmask.s_addr = htonl(0xffffffff << (32 - bits));
		else
			netmask.s_addr = INADDR_ANY;

		memset(&dest, 0, sizeof(dest));
		memcpy(&dest.s_addr, &v4proposal->rtstatic[i], bytes);
		dest.s_addr = dest.s_addr & netmask.s_addr;
		i += bytes;

		memcpy(&gateway, &v4proposal->rtstatic[i], sizeof(gateway));
		i += sizeof(gateway);

		if (gateway.s_addr == INADDR_ANY)
			v4_add_direct_route(v4proposal->rdomain, dest,
			    netmask, iface);
		else
			v4_add_route(v4proposal->rdomain, dest, netmask,
			    gateway, iface,
			    RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFA,
			    RTF_GATEWAY | RTF_STATIC);
	}
}

void
v4_resolv_conf_contents(struct imsg_v4proposal *v4proposal)
{
	FILE		*fp;
	struct in_addr	 server;
	char		*src;
	int		 i, servercnt;

	fp = fopen("/etc/resolv.conf", "w");
	if (fp == NULL) {
		log_warn("/etc/resolv.conf");
		return;
	}

	fprintf(fp, "# Generated by netcfgd\n");

	if ((v4proposal->addrs & RTA_SEARCH) != 0)
		fprintf(fp, "search %*s\n", v4proposal->rtsearch_len,
		    v4proposal->rtsearch);

	if ((v4proposal->addrs & RTA_DNS) != 0) {
		servercnt = v4proposal->rtdns_len / sizeof(struct in_addr);
		src = v4proposal->rtdns;
		for (i = 0; i < servercnt; i++) {
			memcpy(&server.s_addr, src, sizeof(server.s_addr));
			fprintf(fp, "nameserver %s\n", inet_ntoa(server));
			src += sizeof(struct in_addr);
		}
	}

	if (fflush(fp) == EOF)
		log_warn("/etc/resolv.conf");
	fclose(fp);

	/* XXX resolv.conf.tail */
}
