/*	$OpenBSD$	*/

/*
 * Copyright (c) 2017 Kenneth R Westerback <krw@openbsd.org>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <resolv.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include "log.h"
#include "netcfgd.h"
#include "engine.h"

__dead void	 engine_shutdown(void);
void		 engine_sig_handler(int sig, short, void *);
void		 engine_dispatch_frontend(int, short, void *);
void		 engine_dispatch_main(int, short, void *);
void		 engine_showinfo_ctl(struct imsg *);
void		 engine_process_v4proposal(struct imsg *);
void		 engine_process_v6proposal(struct imsg *);
void		 engine_kill_proposal(int);
void		 engine_show_v4proposal(struct imsg *,
		     struct imsg_v4proposal *, struct ctl_policy_id *);
void		 engine_show_v6proposal(struct imsg *,
		     struct imsg_v6proposal *, struct ctl_policy_id *);
void		 engine_set_source_state(struct imsg *);
void		 engine_supersede_v4proposal(struct imsg_v4proposal *);

struct netcfgd_conf	*engine_conf;
struct imsgev		*iev_frontend;
struct imsgev		*iev_main;

TAILQ_HEAD(proposal_head, proposal_entry) proposal_queue;

void
engine_sig_handler(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		engine_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
engine(int debug, int verbose)
{
	struct event	 ev_sigint, ev_sigterm;
	struct passwd	*pw;

	engine_conf = config_new_empty();

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(NETCFGD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	netcfgd_process = PROC_ENGINE;
	setproctitle(log_procnames[netcfgd_process]);
	log_procinit(log_procnames[netcfgd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler(s). */
	signal_set(&ev_sigint, SIGINT, engine_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, engine_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the main process. */
	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);

	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = engine_dispatch_main;

	TAILQ_INIT(&proposal_queue);

	/* Setup event handlers. */
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	event_dispatch();

	engine_shutdown();
}


__dead void
engine_shutdown(void)
{
	struct interface	*ifp;

	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	config_clear(engine_conf);

	free(iev_frontend);
	free(iev_main);

	/* Discard proposals. */
	while ((ifp = LIST_FIRST(&engine_conf->interface_list)) != NULL) {
		free(ifp->p_dhclient);
		free(ifp->p_v4static);
		free(ifp->p_slaac);
		free(ifp->p_v6static);
		free(ifp);
	}

	log_info("engine exiting");
	exit(0);
}

int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_frontend, type, 0, pid, -1,
	    data, datalen));
}

int
engine_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1,
	    data, datalen));
}

void
engine_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0, payload;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_LOG_LEVEL:
			memcpy(&payload, imsg.data, sizeof(payload));
			log_setverbose(payload);
			break;
		case IMSG_CTL_KILL_PROPOSAL:
			memcpy(&payload, imsg.data, sizeof(payload));
			engine_kill_proposal(payload);
			break;
		case IMSG_CTL_SHOW_PROPOSALS:
			engine_showinfo_ctl(&imsg);
			break;
		case IMSG_CTL_SET_SOURCE_STATE:
			engine_set_source_state(&imsg);
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_dispatch_main(int fd, short event, void *bula)
{
	struct imsg			 imsg;
	static struct netcfgd_conf	*nconf;
	struct interface		*ifp;
	struct imsgev			*iev = bula;
	struct imsgbuf			*ibuf;
	ssize_t				 n;
	int				 shut = 0;
	unsigned int			 index;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_SOCKET_IPC:
			/*
			 * Setup pipe and event handler to the frontend
			 * process.
			 */
			if (iev_frontend) {
				log_warnx("%s: received unexpected imsg fd "
				    "to engine", __func__);
				break;
			}
			if ((fd = imsg.fd) == -1) {
				log_warnx("%s: expected to receive imsg fd to "
				   "engine but didn't receive any", __func__);
				break;
			}

			iev_frontend = malloc(sizeof(struct imsgev));
			if (iev_frontend == NULL)
				fatal(NULL);

			imsg_init(&iev_frontend->ibuf, fd);
			iev_frontend->handler = engine_dispatch_frontend;
			iev_frontend->events = EV_READ;

			event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
			iev_frontend->events, iev_frontend->handler,
			    iev_frontend);
			event_add(&iev_frontend->ev, NULL);
			break;
		case IMSG_RECONF_CONF:
			if ((nconf = malloc(sizeof(struct netcfgd_conf))) == NULL)
				fatal(NULL);
			memcpy(nconf, imsg.data, sizeof(struct netcfgd_conf));
			LIST_INIT(&nconf->interface_list);
			break;
		case IMSG_RECONF_INTERFACE:
			if ((ifp = malloc(sizeof(struct interface))) == NULL)
				fatal(NULL);
			memcpy(ifp, imsg.data, sizeof(struct interface));
			index = if_nametoindex(ifp->name);
			if (index == 0)
				log_warn("%s", ifp->name);
			else {
				ifp->ifindex = index;
				LIST_INSERT_HEAD(&nconf->interface_list, ifp,
				    entry);
			}
			break;
		case IMSG_RECONF_END:
			merge_config(engine_conf, nconf);
			nconf = NULL;
			break;
		case IMSG_SEND_V4PROPOSAL:
			engine_process_v4proposal(&imsg);
			break;
		case IMSG_SEND_V6PROPOSAL:
			engine_process_v6proposal(&imsg);
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_showinfo_ctl(struct imsg *imsg)
{
	struct ctl_policy_id	 cpid;
	struct interface	*ifp;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_PROPOSALS:
		memcpy(&cpid, imsg->data, sizeof(cpid));
		LIST_FOREACH(ifp, &engine_conf->interface_list, entry) {
			if (ifp->p_dhclient != NULL)
				engine_show_v4proposal(imsg, ifp->p_dhclient,
				    &cpid);
			if (ifp->p_v4static != NULL)
				engine_show_v4proposal(imsg, ifp->p_v4static,
				    &cpid);
			if (ifp->p_slaac != NULL)
				engine_show_v6proposal(imsg, ifp->p_slaac,
				    &cpid);
			if (ifp->p_v6static != NULL)
				engine_show_v6proposal(imsg, ifp->p_v6static,
				    &cpid);
		}
		engine_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

void
engine_process_v4proposal(struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct interface	*ifp;
	struct imsg_v4proposal	*p4;

	if ((p4 = malloc(sizeof(struct imsg_v4proposal))) == NULL)
		fatal(NULL);
	memcpy(p4, imsg->data, sizeof(struct imsg_v4proposal));

	/* Discard proposals for unconfigured interfaces or sources. */
	LIST_FOREACH(ifp, &engine_conf->interface_list, entry) {
		if (ifp->ifindex == p4->index) {
			if (p4->source == RTP_PROPOSAL_DHCLIENT &&
			    ifp->dhclient == 0) {
				ifp = NULL;
				log_warnx("%s not configured for dhclient",
				    if_indextoname(p4->index, ifname));

			}
			else if (p4->source == RTP_PROPOSAL_STATIC &&
			    ifp->v4static == 0) {
				ifp = NULL;
				log_warnx("%s not configured for static v4",
				    if_indextoname(p4->index, ifname));
			}
			break;
		}
	}
	if (ifp == NULL) {
		log_warnx("'%s' proposals can't be accepted",
		    if_indextoname(p4->index, ifname));
		free(p4);
		return;
	}

	switch (p4->source) {
	case RTP_PROPOSAL_DHCLIENT:
		if (p4->kill) {
			engine_kill_proposal(p4->xid);
			free(p4);
		} else if (ifp->p_dhclient != NULL &&
		    p4->xid == ifp->p_dhclient->xid) {
			/* Discard duplicate proposals. */
			log_warnx("duplicate dhclient proposal discarded");
			free(p4);
			return;
		} else {
			if (ifp->p_dhclient != NULL) {
				log_warnx("dhclient proposal superseded");
				engine_kill_proposal(ifp->p_dhclient->xid);
			} else
				log_warnx("new dhclient proposal");
			ifp->p_dhclient = p4;
			engine_add_v4address(ifp->p_dhclient);
			engine_add_v4routes(ifp->p_dhclient);
		}
		break;
	case RTP_PROPOSAL_STATIC:
		if (p4->kill) {
			engine_kill_proposal(p4->xid);
			free(p4);
		} else if (ifp->p_v4static &&
		    p4->xid == ifp->p_v4static->xid) {
			/* Discard duplicate proposals. */
			log_warnx("duplicate v4 static proposal dscarded");
			free(p4);
			return;
		} else {
			if (ifp->p_v4static != NULL) {
				/* Supersede current static proposal. */
				log_warnx("v4 static proposal superseded");
				engine_kill_proposal(ifp->p_v4static->xid);
			}
			ifp->p_dhclient = p4;
			engine_add_v4address(ifp->p_dhclient);
			engine_add_v4routes(ifp->p_dhclient);
		}
		break;
	default:
		log_warnx("Unknown v4 source: %d", p4->source);
		return;
	}

	engine_resolv_conf_contents(ifp);
}

void
engine_process_v6proposal(struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct interface	*ifp;
	struct imsg_v6proposal	*p6;

	if ((p6 = malloc(sizeof(struct imsg_v6proposal))) == NULL)
		fatal(NULL);
	memcpy(p6, imsg->data, sizeof(struct imsg_v6proposal));

	/* Discard proposals for unconfigured interfaces or sources. */
	LIST_FOREACH(ifp, &engine_conf->interface_list, entry) {
		if (ifp->ifindex == p6->index) {
			if (p6->source == RTP_PROPOSAL_SLAAC &&
			    ifp->dhclient == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for slaac",
				    if_indextoname(p6->index, ifname));

			}
			else if (p6->source == RTP_PROPOSAL_STATIC &&
			    ifp->v6static == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for static v6",
				    if_indextoname(p6->index, ifname));
			}
			break;
		}
	}
	if (ifp == NULL) {
		log_warnx("'%s' proposals can't be accepted",
		    if_indextoname(p6->index, ifname));
		free(p6);
		return;
	}

	switch (p6->source) {
	case RTP_PROPOSAL_SLAAC:
		if (p6->kill) {
			engine_kill_proposal(p6->xid);
		} else if (ifp->p_slaac != NULL &&
		    p6->xid == ifp->p_slaac->xid) {
			/* Discard duplicate proposals. */
			log_warnx("duplicate slaac proposal dscarded");
			free(p6);
			return;
		} else {
			if (ifp->p_slaac != NULL) {
				log_warnx("slaac proposal superseded");
				engine_kill_proposal(ifp->p_slaac->xid);
			}
			ifp->p_slaac = p6;
			engine_add_v6address(ifp->p_slaac);
			engine_add_v6routes(ifp->p_slaac);
		}
		break;
	case RTP_PROPOSAL_STATIC:
		if (p6->kill) {
			engine_kill_proposal(p6->xid);
		} else if (ifp->p_v6static &&
		    p6->xid == ifp->p_v6static->xid) {
			/* Discard duplicate proposals. */
			log_warnx("duplicate v4 static proposal dscarded");
			free(p6);
			return;
		} else {
			/* Supersede current dhclient proposal. */
			if (ifp->p_v6static != NULL) {
				log_warnx("v6static proposal superseded");
				engine_kill_proposal(ifp->p_v6static->xid);
			}
			ifp->p_v6static = p6;
			engine_add_v6address(ifp->p_v6static);
			engine_add_v6routes(ifp->p_v6static);
		}
		break;
	default:
		log_warnx("Unknown v6 source: %d", p6->source);
		return;
	}

	engine_resolv_conf_contents(ifp);
}

void
engine_kill_proposal(int xid)
{
	struct imsg_supersede_proposal	sp;
	struct interface *ifp;

	memset(&sp, 0, sizeof(sp));
	sp.xid = xid;

	LIST_FOREACH(ifp, &engine_conf->interface_list, entry) {
		if (ifp->p_dhclient != NULL && ifp->p_dhclient->xid == xid) {
			sp.source = RTP_PROPOSAL_DHCLIENT;
			sp.rdomain = ifp->p_dhclient->rdomain;
			sp.index = ifp->p_dhclient->index;
			engine_delete_v4routes(ifp->p_dhclient);
			engine_delete_v4address(ifp->p_dhclient);
			free(ifp->p_dhclient);
			ifp->p_dhclient = NULL;
			break;
		}
		if (ifp->p_v4static != NULL && ifp->p_v4static->xid == xid) {
			sp.source = RTP_PROPOSAL_STATIC;
			sp.rdomain = ifp->p_v4static->rdomain;
			sp.index = ifp->p_v4static->index;
			engine_delete_v4routes(ifp->p_v4static);
			engine_delete_v4address(ifp->p_v4static);
			free(ifp->p_v4static);
			ifp->p_v4static = NULL;
			break;
		}
		if (ifp->p_slaac != NULL && ifp->p_slaac->xid == xid) {
			sp.source = RTP_PROPOSAL_SLAAC;
			sp.rdomain = ifp->p_slaac->rdomain;
			sp.index = ifp->p_slaac->index;
			engine_delete_v6routes(ifp->p_slaac);
			engine_delete_v6address(ifp->p_slaac);
			free(ifp->p_slaac);
			ifp->p_slaac = NULL;
			break;
		}
		if (ifp->p_v6static != NULL && ifp->p_v6static->xid == xid) {
			sp.source = RTP_PROPOSAL_STATIC;
			sp.rdomain = ifp->p_v6static->rdomain;
			sp.index = ifp->p_v6static->index;
			engine_delete_v6routes(ifp->p_v6static);
			engine_delete_v6address(ifp->p_v6static);
			free(ifp->p_v6static);
			ifp->p_dhclient = NULL;
			break;
		}
	}

	if (ifp == NULL)
		log_warnx("No proposal with xid %0x to kill", xid);
	else
		engine_imsg_compose_frontend(IMSG_SUPERSEDE_PROPOSAL, 0, &sp,
		    sizeof(sp));
}

void
engine_show_v4proposal(struct imsg *imsg, struct imsg_v4proposal *p,
    struct ctl_policy_id *cpid)
{
	struct imsg_v4proposal	imsg_v4proposal;

	if (cpid->ifindex != 0 && p->index != cpid->ifindex)
		return;
	if (cpid->source != 0 && cpid->source != p->source)
		return;

	memcpy(&imsg_v4proposal, p, sizeof(imsg_v4proposal));
	engine_imsg_compose_frontend(IMSG_CTL_REPLY_V4PROPOSAL, imsg->hdr.pid,
	    &imsg_v4proposal, sizeof(imsg_v4proposal));
}

void
engine_show_v6proposal(struct imsg *imsg, struct imsg_v6proposal *p,
    struct ctl_policy_id *cpid)
{
	struct imsg_v6proposal	imsg_v6proposal;

	if (cpid->ifindex != 0 && p->index != cpid->ifindex)
		return;
	if (cpid->source != 0 && cpid->source != p->source)
		return;

	memcpy(&imsg_v6proposal, p, sizeof(imsg_v6proposal));
	engine_imsg_compose_frontend(IMSG_CTL_REPLY_V6PROPOSAL, imsg->hdr.pid,
	    &imsg_v6proposal, sizeof(imsg_v6proposal));
}

void
engine_set_source_state(struct imsg *imsg)
{
	struct ctl_policy_id	 cpid;
	struct interface	*ifp;
	int			 newstate = 1;

	memcpy(&cpid, imsg->data, sizeof(cpid));

	LIST_FOREACH(ifp, &engine_conf->interface_list, entry) {
		if (ifp->ifindex != cpid.ifindex && cpid.ifindex != 0)
			continue;
		if (cpid.source < 0) {
			cpid.source = -cpid.source;
			newstate = 0;
		}
		switch (cpid.source) {
		case RTP_PROPOSAL_DHCLIENT:
			ifp->dhclient = newstate;
			break;
		case RTP_PROPOSAL_SLAAC:
			ifp->slaac = newstate;
			break;
		case RTP_PROPOSAL_STATIC:
			/* XXX v6static */
			ifp->v4static = newstate;
			break;
		default:
			break;
		}
	}
}

void
engine_supersede_v4proposal(struct imsg_v4proposal *v4proposal)
{
}

void
engine_resolv_conf_contents(struct interface *ifp)
{
	char			 buf[INET6_ADDRSTRLEN];
	struct in_addr		 v4server;
	struct in6_addr		 v6server;
	struct imsg_v4proposal	*dhclient, *v4static;
	struct imsg_v6proposal	*slaac, *v6static;
	const char		*pbuf;
	char			*search[4], *nss[MAXNS], *contents;
	char			*src;
	int			 i, j, rslt, servercnt;

	/* XXX Actually need to process *ALL* interfaces! */

	memset(nss, 0, sizeof(nss));

	dhclient = ifp->p_dhclient;
	v4static = ifp->p_v4static;
	slaac = ifp->p_slaac;
	v6static = ifp->p_v6static;

	search[0] = NULL;
	if (dhclient && dhclient->rtsearch_len > 0) {
		rslt = asprintf(&search[0], "%.*s", dhclient->rtsearch_len,
		    dhclient->rtsearch);
		if (rslt == -1)
			 search[0] = NULL;
	}
	search[1] = NULL;
	if (v4static && v4static->rtsearch_len > 0) {
		rslt = asprintf(&search[1], "%.*s", v4static->rtsearch_len,
		    v4static->rtsearch);
		if (rslt == -1)
			search[1] = NULL;
	}
	search[2] = NULL;
	if (slaac && slaac->rtsearch_len > 0) {
		rslt = asprintf(&search[2], "%.*s", slaac->rtsearch_len,
		    slaac->rtsearch);
		if (rslt == -1)
			search[2] = NULL;
	}
	search[3] = NULL;
	if (v6static && v6static->rtsearch_len > 0) {
		rslt = asprintf(&search[3], "%.*s", v6static->rtsearch_len,
		    v6static->rtsearch);
		if (rslt == -1)
			search[3] = NULL;
	}

	j = 0;

	if (dhclient != NULL) {
		servercnt = dhclient->rtdns_len / sizeof(struct in_addr);
		if (servercnt > MAXNS)
			servercnt = MAXNS;
		src = dhclient->rtdns;
		for (i = 0; i < servercnt; i++, j++) {
			memcpy(&v4server.s_addr, src, sizeof(v4server.s_addr));
			rslt = asprintf(&nss[j], "nameserver %s\n",
			    inet_ntoa(v4server));
			if (rslt == -1) {
				nss[j] = NULL;
				log_warn("IPv4 nameserver");
			}
			src += sizeof(struct in_addr);
		}
	}
	if (v4static != NULL) {
		servercnt = v4static->rtdns_len / sizeof(struct in_addr);
		if (servercnt > MAXNS - j)
			servercnt = MAXNS - j;
		src = v4static->rtdns;
		for (i = 0; i < servercnt; i++, j++) {
			memcpy(&v4server.s_addr, src, sizeof(v4server.s_addr));
			rslt = asprintf(&nss[j], "nameserver %s\n",
			    inet_ntoa(v4server));
			if (rslt == -1) {
				nss[j] = NULL;
				log_warn("IPv4 nameserver");
			}
			src += sizeof(struct in_addr);
		}
	}

	if (slaac != NULL) {
		servercnt = slaac->rtdns_len / sizeof(struct in6_addr);
		if (servercnt > MAXNS - j)
			servercnt = MAXNS - j;
		src = slaac->rtdns;
		for (i = 0; i < servercnt; i++, j++) {
			memcpy(&v6server, src, sizeof(v6server));
			pbuf = inet_ntop(AF_INET6, &v6server, buf,
			    INET_ADDRSTRLEN);
			if (pbuf) {
				rslt = asprintf(&nss[j], "nameserver %s\n",
				    pbuf);
				if (rslt == -1) {
					nss[j] = NULL;
					log_warn("IPv6 nameserver");
				}
			} else {
				nss[j] = NULL;
				log_warn("IPv6 nameserver");
			}
			src += sizeof(struct in_addr);
		}
	}
	if (v6static != NULL) {
		servercnt = v6static->rtdns_len / sizeof(struct in6_addr);
		if (servercnt > MAXNS - j)
			servercnt = MAXNS - j;
		src = v6static->rtdns;
		for (i = 0; i < servercnt; i++, j++) {
			memcpy(&v6server, src, sizeof(v6server));
			pbuf = inet_ntop(AF_INET6, &v6server, buf,
			    INET_ADDRSTRLEN);
			if (pbuf) {
				rslt = asprintf(&nss[j], "nameserver %s\n",
				    pbuf);
				if (rslt == -1) {
					nss[j] = NULL;
					log_warn("IPv6 nameserver");
				}
			} else {
				nss[j] = NULL;
				log_warn("IPv6 nameserver");
			}
			src += sizeof(struct in_addr);
		}
	}

	if (search[0] || search[1] || search[2] || search[3]) {
		rslt = asprintf(&contents, "# Created by netcfgd\n"
		    "search %s %s %s %s\n"
		    "%s%s%s",
		    search[0] ? search[0] : "",
		    search[1] ? search[1] : "",
		    search[2] ? search[2] : "",
		    search[3] ? search[3] : "",
		    nss[0] ? nss[0] : "",
		    nss[1] ? nss[1] : "",
		    nss[2] ? nss[2] : "");
	} else {
		rslt = asprintf(&contents, "# Created by netcfgd\n"
		    "%s%s%s",
		    nss[0] ? nss[0] : "",
		    nss[1] ? nss[1] : "",
		    nss[2] ? nss[2] : "");
	}
	if (rslt == -1) {
		log_warn("resolv.conf contents");
		contents = NULL;
	} else {
		engine_imsg_compose_main(IMSG_RESOLV_CONF, 0, contents,
		    rslt + 1);
		free(contents);
	}

	for (i = 0; i < MAXNS; i++)
		free(nss[i]);
	for (i = 0; i < 4; i++)
		free(search[i]);
	free(contents);
}
