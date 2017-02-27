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
void	v4_add_static_routes(struct imsg_v4proposal *);
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

	log_warnx("Executing v4 proposal");

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
	if (v4proposal.mtu != 0) {
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
	v4_add_static_routes(&v4proposal);

	/* 6) Update resolv.conf. */
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
v4_add_static_routes(struct imsg_v4proposal *v4proposal)
{
	struct iovec		iov[6];
	struct sockaddr_in	dest, netmask, gateway, ifa;
	struct rt_msghdr	rtm;
	struct sockaddr_rtlabel label;
	uint8_t		       *src;
	size_t			bytes, saddrlen, srclen;
	int			bits, i, iovcnt;

	memset(&dest, 0, sizeof(dest));
	memset(&netmask, 0, sizeof(netmask));
	memset(&gateway, 0, sizeof(gateway));
	memset(&ifa, 0, sizeof(ifa));

	saddrlen = sizeof(dest.sin_addr.s_addr);

	dest.sin_len = netmask.sin_len = gateway.sin_len = ifa.sin_len =
	    sizeof(dest);
	dest.sin_family = netmask.sin_family = gateway.sin_family =
	    ifa.sin_family = AF_INET;

	ifa.sin_addr.s_addr = v4proposal->ifa.s_addr;

	/* The order *MUST* be RTM+DEST+GATEWAY+NETMASK[+IFA][+LABEL]! */
	iov[0].iov_base = &rtm;
	iov[0].iov_len = sizeof(rtm);
	iov[1].iov_base = &dest;
	iov[1].iov_len = sizeof(dest);
	iov[2].iov_base = &gateway;
	iov[2].iov_len = sizeof(gateway);
	iov[3].iov_base = &netmask;
	iov[3].iov_len = sizeof(netmask);

	/* Build RTM header */
	memset(&rtm, 0, sizeof(rtm));

	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_type = RTM_ADD;
	rtm.rtm_tableid = v4proposal->rdomain;
	rtm.rtm_priority = RTP_NONE;

	src = v4proposal->rtstatic;
	srclen = *src++;
	while (srclen) {

		bits = *src++;
		srclen--;
		bytes = (bits + 7) / 8;
		if (srclen < bytes || bytes > saddrlen) {
			log_warnx("invalid static routes");
			return;
		}

		memset(&dest.sin_addr.s_addr, 0, saddrlen);
		memcpy(&dest.sin_addr.s_addr, src, bytes);
		src += bytes;
		srclen -= bytes;

		/* Construct netmask from value of 'bits'. */
		if (bits)
			netmask.sin_addr.s_addr = htonl(0xffffffff <<
			    (32 - bits));
		else
			netmask.sin_addr.s_addr = INADDR_ANY;

		dest.sin_addr.s_addr = dest.sin_addr.s_addr &
		    netmask.sin_addr.s_addr;

		if (sizeof(gateway.sin_addr.s_addr) > srclen) {
			log_warnx("invalid static routes");
			return;
		}
		memcpy(&gateway.sin_addr.s_addr, src, saddrlen);
		src += saddrlen;
		srclen -= saddrlen;

		iovcnt = 4;
		rtm.rtm_msglen = sizeof(rtm) + sizeof(struct sockaddr_in) * 3;
		rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
		rtm.rtm_flags = RTF_STATIC;

		if (gateway.sin_addr.s_addr == INADDR_ANY) {
			/* Adding direct route. */
			rtm.rtm_flags |= RTF_CLONING;
			gateway.sin_addr.s_addr = v4proposal->ifa.s_addr;
		} else {
			/* Adding indirect route. */
			rtm.rtm_addrs |= RTA_IFA;
			rtm.rtm_flags |= RTF_GATEWAY;
		}

		if (rtm.rtm_addrs & RTA_IFA) {
			rtm.rtm_msglen += sizeof(ifa);
			iov[iovcnt].iov_base = &netmask;
			iov[iovcnt].iov_len = sizeof(netmask);
			iovcnt++;
		}

		/* Identify the route as our creation. */
		memset(&label, 0, sizeof(label));
		label.sr_len = sizeof(label);
		label.sr_family = AF_UNSPEC;

		i = snprintf(label.sr_label, sizeof(label.sr_label),
		    "NETCFGD %d", (int)getpid());
		if (i == -1) {
			log_warn("creating route label");
			return;
		}

		rtm.rtm_addrs |= RTA_LABEL;
		rtm.rtm_msglen += sizeof(label);
		iov[iovcnt].iov_base = &label;
		iov[iovcnt].iov_len = sizeof(label);
		iovcnt++;

		if (writev(kr_state.route_fd, iov, iovcnt) == -1) {
			log_warn("failed to add v4 static route (%d/%d)",
			    kr_state.route_fd, iovcnt);
		}
	}
}

void
v4_resolv_conf_contents(struct imsg_v4proposal *v4proposal)
{
	FILE *fp;

	fp = fopen("/etc/resolv.conf", "w");
	if (fp == NULL) {
		log_warn("/etc/resolv.conf");
		return;
	}

	fprintf(fp, "# Generated by netcfgd\n");

	if (strlen(v4proposal->rtsearch) > 0)
		fprintf(fp, "search %s\n", v4proposal->rtsearch);
	if (v4proposal->dns[0].s_addr != INADDR_ANY)
		fprintf(fp, "nameserver %s\n", inet_ntoa(v4proposal->dns[0]));
	if (v4proposal->dns[1].s_addr != INADDR_ANY)
		fprintf(fp, "nameserver %s\n", inet_ntoa(v4proposal->dns[1]));
	if (v4proposal->dns[2].s_addr != INADDR_ANY)
		fprintf(fp, "nameserver %s\n", inet_ntoa(v4proposal->dns[2]));
	if (v4proposal->dns[3].s_addr != INADDR_ANY)
		fprintf(fp, "nameserver %s\n", inet_ntoa(v4proposal->dns[3]));

	if (fflush(fp) == EOF)
		log_warn("/etc/resolv.conf");
	fclose(fp);

	/* XXX resolv.conf.tail */
}
