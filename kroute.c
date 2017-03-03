/*	$OpenBSD$ */

/*
 * Copyright (c) 2017 Kenneth R Westerback <krw@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "netcfgd.h"

struct kr_state	kr_state;

void	kr_dispatch_msg(int, short, void *);
int	kr_get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
void	forward_v4proposal(struct rt_msghdr *, struct sockaddr **);
void	forward_v6proposal(struct rt_msghdr *, struct sockaddr **);
void	copy_sockaddr_in(struct in_addr *, struct sockaddr *);
void	copy_sockaddr_in6(struct in6_addr *, struct sockaddr *);
void	ack_proposal(struct rt_msghdr *);

int
kr_init(void)
{
	int		opt = 0, rcvbuf, default_rcvbuf, rtfilter;
	socklen_t	optlen;

	if ((kr_state.route_fd = socket(AF_ROUTE,
	    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, AF_INET)) == -1) {
		log_warn("kr_init: route socket");
		return (-1);
	}

	/* Not interested in my own messages. */
	if (setsockopt(kr_state.route_fd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		log_warn("kr_init: setsockopt");	/* not fatal */

	/* Only care about proposals. */
	rtfilter = ROUTE_FILTER(RTM_PROPOSAL);
	if (setsockopt(kr_state.route_fd, PF_ROUTE, ROUTE_MSGFILTER,
	    &rtfilter, sizeof(rtfilter)) == -1) {
		log_warn("setsockopt(ROUTE_MSGFILTER): %s", strerror(errno));
		return (-1);
	}

	/* Grow receive buffer, don't want to miss messages. */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kr_state.route_fd, SOL_SOCKET, SO_RCVBUF,
	    &default_rcvbuf, &optlen) == -1)
		log_warn("kr_init getsockopt SOL_SOCKET SO_RCVBUF");
	else
		for (rcvbuf = NETCFGD_MAX_RTSOCK_BUF;
		    rcvbuf > default_rcvbuf &&
		    setsockopt(kr_state.route_fd, SOL_SOCKET, SO_RCVBUF,
		    &rcvbuf, sizeof(rcvbuf)) == -1 && errno == ENOBUFS;
		    rcvbuf /= 2)
			;	/* nothing */

	if ((kr_state.inet_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		log_warn("kr_init: inet socket");
		return (-1);
	}

	kr_state.pid = getpid();

	event_set(&kr_state.ev, kr_state.route_fd, EV_READ | EV_PERSIST,
	    kr_dispatch_msg, NULL);
	event_add(&kr_state.ev, NULL);

	return (0);
}

/* ARGSUSED */
void
kr_dispatch_msg(int fd, short event, void *bula)
{
	char			 buf[NETCFGD_RT_BUF_SIZE];
	struct rt_msghdr	*rtm;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	char			*next;
	ssize_t			 n;
	size_t			 len, offset;
	int			 v6;

	if ((n = read(kr_state.route_fd, &buf, sizeof(buf))) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		log_warn("dispatch_rtmsg: read error");
		event_loopexit(NULL);
		return;
	}

	if (n == 0) {
		log_warnx("routing socket closed");
		event_loopexit(NULL);
		return;
	}

	len = n;
	for (offset = 0; offset < len; offset += rtm->rtm_msglen) {
		next = buf + offset;
		rtm = (struct rt_msghdr *)next;
		if (len < offset + sizeof(u_short) ||
		    len < offset + rtm->rtm_msglen)
			fatalx("rtmsg_process: partial rtm in buffer");
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		sa = (struct sockaddr *)(next + rtm->rtm_hdrlen);
		v6 = kr_get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

		switch (rtm->rtm_type) {
		case RTM_PROPOSAL:
			if ((rtm->rtm_flags & RTF_PROTO1) != 0) {
				log_warnx("Seeing RTF_PROTO1");
				break;
			}
			if (v6)
				forward_v6proposal(rtm, rti_info);
			else
				forward_v4proposal(rtm, rti_info);
			ack_proposal(rtm);
			break;
		default:
			/* ignore for now */
			break;
		}
	}

	return;
}

#define	ROUNDUP(a)	\
    (((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))

int
kr_get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i, v6 = 1;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			if (sa->sa_family == AF_INET)
				v6 = 0;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
	return (v6);
}

void
forward_v4proposal(struct rt_msghdr *rtm, struct sockaddr **rti_info)
{
	struct imsg_v4proposal	 proposal;

	memset(&proposal, 0, sizeof(proposal));

	proposal.addrs = rtm->rtm_addrs;
	proposal.inits = rtm->rtm_inits;
	proposal.xid = rtm->rtm_seq;
	proposal.index = rtm->rtm_index;
	proposal.source = rtm->rtm_priority;
	proposal.kill = (rtm->rtm_flags & RTF_UP) == 0;

	if (proposal.inits & RTV_MTU) {
		proposal.mtu = rtm->rtm_rmx.rmx_mtu;
	}

	if (rti_info[RTAX_STATIC] != NULL) {
		struct sockaddr_rtstatic *rtstatic;
		rtstatic = (struct sockaddr_rtstatic *)rti_info[RTAX_STATIC];
		proposal.rtstatic_len = rtstatic->sr_len -
		    offsetof(struct sockaddr_rtstatic, sr_static);
		memcpy(proposal.rtstatic, rtstatic->sr_static,
		    proposal.rtstatic_len);
	}
	if (rti_info[RTAX_SEARCH] != NULL) {
		struct sockaddr_rtsearch *rtsearch;
		rtsearch = (struct sockaddr_rtsearch *)rti_info[RTAX_SEARCH];
		proposal.rtsearch_len = rtsearch->sr_len -
		    offsetof(struct sockaddr_rtsearch, sr_search);
		memcpy(proposal.rtsearch, rtsearch->sr_search,
		   proposal.rtsearch_len);
	}
	if (rti_info[RTAX_DNS] != NULL) {
		struct sockaddr_rtdns *rtdns;
		rtdns = (struct sockaddr_rtdns *)rti_info[RTAX_DNS];
		proposal.rtdns_len = rtdns->sr_len -
		   offsetof(struct sockaddr_rtdns, sr_dns);
		memcpy(proposal.rtdns, rtdns->sr_dns, proposal.rtdns_len);
	}

	copy_sockaddr_in(&proposal.ifa, rti_info[RTAX_IFA]);
	copy_sockaddr_in(&proposal.netmask, rti_info[RTAX_NETMASK]);

	main_imsg_compose_engine(IMSG_SEND_V4PROPOSAL, 0, &proposal,
	    sizeof(proposal));
}

void
forward_v6proposal(struct rt_msghdr *rtm, struct sockaddr **rti_info)
{
	struct imsg_v6proposal	 proposal;

	memset(&proposal, 0, sizeof(proposal));

	proposal.addrs = rtm->rtm_addrs;
	proposal.inits = rtm->rtm_inits;
	proposal.xid = rtm->rtm_seq;
	proposal.index = rtm->rtm_index;
	proposal.source = rtm->rtm_priority;
	proposal.kill = (rtm->rtm_flags & RTF_UP) == 0;

	if (proposal.inits & RTV_MTU) {
		proposal.mtu = rtm->rtm_rmx.rmx_mtu;
	}

	if (rti_info[RTAX_STATIC] != NULL) {
		struct sockaddr_rtstatic *rtstatic;
		rtstatic = (struct sockaddr_rtstatic *)rti_info[RTAX_STATIC];
		memcpy(&proposal.rtstatic, rtstatic->sr_static,
		    sizeof(proposal.rtstatic));
	}
	if (rti_info[RTAX_SEARCH] != NULL) {
		struct sockaddr_rtsearch *rtsearch;
		rtsearch = (struct sockaddr_rtsearch *)rti_info[RTAX_SEARCH];
		memcpy(&proposal.rtsearch, rtsearch->sr_search,
		    sizeof(proposal.rtsearch));
	}
	if (rti_info[RTAX_DNS] != NULL) {
		struct sockaddr_rtdns *rtdns;
		rtdns = (struct sockaddr_rtdns *)rti_info[RTAX_DNS];
		memcpy(proposal.rtdns, rtdns->sr_dns, sizeof(proposal.rtdns));
	}

	copy_sockaddr_in6(&proposal.ifa, rti_info[RTAX_IFA]);
	copy_sockaddr_in6(&proposal.netmask, rti_info[RTAX_NETMASK]);
}

void
copy_sockaddr_in(struct in_addr *in_addr, struct sockaddr *sa)
{
	struct sockaddr_in	*sa_in;

	if (sa == NULL)
		return;

	sa_in = (struct sockaddr_in *)sa;

	memcpy(in_addr, &sa_in->sin_addr, sizeof(*in_addr));
}

void
copy_sockaddr_in6(struct in6_addr *in6_addr, struct sockaddr *sa)
{
	struct sockaddr_in6	*sa_in6;

	if (sa == NULL)
		return;

	sa_in6 = (struct sockaddr_in6 *)sa;

	memcpy(in6_addr, &sa_in6->sin6_addr, sizeof(*in6_addr));
}

void
ack_proposal(struct rt_msghdr *rtm)
{
	struct rt_msghdr ack;
	ssize_t len;

	memset(&ack, 0, sizeof(ack));

	log_warnx("Attempting to ACK proposal");

	/* Acknowledge receipt of proposal. */
	ack.rtm_version = RTM_VERSION;
	ack.rtm_msglen = sizeof(ack);
	ack.rtm_flags = RTF_PROTO1;
	ack.rtm_type = RTM_PROPOSAL;
	ack.rtm_index = rtm->rtm_index;
	ack.rtm_priority = rtm->rtm_priority;
	ack.rtm_seq = rtm->rtm_seq;
	ack.rtm_tableid = rtm->rtm_tableid;

	len = write(kr_state.route_fd, &ack, sizeof(ack));
	if (len == -1)
		log_warn("ACK proposal");
	else
		log_warnx("wrote %zd bytes to ACK proposal", len);
}
