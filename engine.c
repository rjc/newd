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

#include <errno.h>
#include <event.h>
#include <imsg.h>
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
int		 engine_process_v4proposal(struct imsg *);
int		 engine_process_v6proposal(struct imsg *);
void		 engine_kill_proposal(int);
void		 engine_show_v4proposal(struct imsg *,
		     struct imsg_v4proposal *, struct ctl_policy_id *);
void		 engine_show_v6proposal(struct imsg *,
		     struct imsg_v6proposal *, struct ctl_policy_id *);
void		 engine_set_source_state(struct imsg *);

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
	struct proposal_entry	*p;

	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	config_clear(engine_conf);

	free(iev_frontend);
	free(iev_main);

	/* Discard proposals. */
	while ((p = TAILQ_FIRST(&proposal_queue)) != NULL) {
		free(p->v4proposal);
		free(p->v6proposal);
		free(p);
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
	struct interface_policy		*p;
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
			LIST_INIT(&nconf->policy_list);
			break;
		case IMSG_RECONF_POLICY:
			if ((p = malloc(sizeof(struct interface_policy)))
			    == NULL)
				fatal(NULL);
			memcpy(p, imsg.data,
			    sizeof(struct interface_policy));
			index = if_nametoindex(p->name);
			if (index == 0)
				log_warnx("%s:%s", p->name, strerror(errno));
			else {
				p->ifindex = index;
				LIST_INSERT_HEAD(&nconf->policy_list, p,
				    entry);
			}
			break;
		case IMSG_RECONF_END:
			merge_config(engine_conf, nconf);
			nconf = NULL;
			break;
		case IMSG_SEND_V4PROPOSAL:
			if (engine_process_v4proposal(&imsg) == 0) {
				engine_imsg_compose_main(
				    IMSG_EXECUTE_V4PROPOSAL,
				    imsg.hdr.pid, imsg.data,
				    sizeof(struct imsg_v4proposal));
			}
			break;
		case IMSG_SEND_V6PROPOSAL:
			if (engine_process_v6proposal(&imsg) == 0) {
				engine_imsg_compose_main(
				    IMSG_EXECUTE_V6PROPOSAL,
				    imsg.hdr.pid, imsg.data,
				    sizeof(struct imsg_v6proposal));
			}
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
	struct proposal_entry	*p;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_PROPOSALS:
		memcpy(&cpid, imsg->data, sizeof(cpid));
		TAILQ_FOREACH(p, &proposal_queue, entry) {
			if (p->v4proposal != NULL)
				engine_show_v4proposal(imsg, p->v4proposal,
				    &cpid);
			else if (p->v6proposal != NULL)
				engine_show_v6proposal(imsg, p->v6proposal,
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

int
engine_process_v4proposal(struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct proposal_entry	*p;
	struct interface_policy	*ifp;
	struct imsg_v4proposal	*p4;

	if ((p4 = malloc(sizeof(struct imsg_v4proposal))) == NULL)
		fatal(NULL);
	memcpy(p4, imsg->data, sizeof(struct imsg_v4proposal));

	/* Discard proposals for unconfigured interfaces or sources. */
	LIST_FOREACH(ifp, &engine_conf->policy_list, entry) {
		if (ifp->ifindex == p4->index) {
			if (p4->source == RTP_PROPOSAL_DHCLIENT &&
			    ifp->dhclient == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for dhclient",
				    if_indextoname(p4->index, ifname));

			}
			else if (p4->source == RTP_PROPOSAL_STATIC &&
			    ifp->statik == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for static v4",
				    if_indextoname(p4->index, ifname));
			}
			break;
		}
	}
	if (ifp == NULL) {
		log_warnx("'%s' proposal can't be accepted",
		    if_indextoname(p4->index, ifname));
		return (1);
	}

	/* Discard duplicate proposals and proposals being killed. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if (p->v4proposal->xid == p4->xid) {
			if (p4->kill == 0) {
				free(imsg);
				log_warnx("proposal already received");
				return (1);
			} else {
				log_warnx("proposal being killed");
				TAILQ_REMOVE(&proposal_queue, p, entry);
				return (0);
			}
		}
	}

	/* Remove superseded proposal. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if ((p->v4proposal->index == p4->index) &&
		    (p->v4proposal->source == p4->source)) {
			log_warnx("proposal being superseded");
			break;
		}
	}
	if (p != NULL)
		TAILQ_REMOVE(&proposal_queue, p, entry);

	/*
	 * Take appropriate action on proposal contents.
	 *
	 * XXX - for now just discard old proposal. In future
	 *       contents may impact actions taken on new
	 *       proposal.
	 */
	if (p != NULL) {
		free(p->v4proposal);
		free(p);
	}

	/* Save new proposal. */
	p = malloc(sizeof(struct proposal_entry));
	if (p == NULL)
		fatal(NULL);
	p->v4proposal = p4;

	TAILQ_INSERT_HEAD(&proposal_queue, p, entry);

	return (0);
}

int
engine_process_v6proposal(struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct proposal_entry	*p;
	struct interface_policy	*ifp;
	struct imsg_v6proposal	*p6;

	if ((p6 = malloc(sizeof(struct imsg_v6proposal))) == NULL)
		fatal(NULL);
	memcpy(p6, imsg->data, sizeof(struct imsg_v6proposal));

	/* Discard proposals for unconfigured interfaces or sources. */
	LIST_FOREACH(ifp, &engine_conf->policy_list, entry) {
		if (ifp->ifindex == p6->index) {
			if (p6->source == RTP_PROPOSAL_SLAAC &&
			    ifp->dhclient == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for slaac",
				    if_indextoname(p6->index, ifname));

			}
			else if (p6->source == RTP_PROPOSAL_STATIC &&
			    ifp->statik == 0) {
				ifp = NULL;
				log_warnx("'%s' not configured for static v6",
				    if_indextoname(p6->index, ifname));
			}
			break;
		}
	}
	if (ifp == NULL) {
		log_warnx("'%s' proposal can't be accepted",
		    if_indextoname(p6->index, ifname));
		return (1);
	}

	/* Discard duplicate proposals and proposals being killed. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if (p->v6proposal->xid == p6->xid) {
			if (p6->kill == 0) {
				free(imsg);
				log_warnx("proposal already received");
				return (1);
			} else {
				log_warnx("proposal being killed");
				TAILQ_REMOVE(&proposal_queue, p, entry);
				return (0);
			}
		}
	}

	/* Remove superseded proposal. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if ((p->v6proposal->index == p6->index) &&
		    (p->v6proposal->source == p6->source)) {
			log_warnx("proposal being superseded");
			break;
		}
	}
	if (p != NULL)
		TAILQ_REMOVE(&proposal_queue, p, entry);

	/*
	 * Take appropriate action on proposal contents.
	 *
	 * XXX - for now just discard old proposal. In future
	 *       contents may impact actions taken on new
	 *       proposal.
	 */
	if (p != NULL) {
		free(p->v6proposal);
		free(p);
	}

	/* Save new proposal. */
	p = malloc(sizeof(struct proposal_entry));
	if (p == NULL)
		fatal(NULL);
	p->v6proposal = p6;

	TAILQ_INSERT_HEAD(&proposal_queue, p, entry);

	return (0);
}

void
engine_kill_proposal(int xid)
{
	struct proposal_entry *p;

	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if ((p->v6proposal != NULL && p->v6proposal->xid == xid) ||
		    (p->v4proposal != NULL && p->v4proposal->xid == xid))
			break;
	}

	if (p != NULL)
		TAILQ_REMOVE(&proposal_queue, p, entry);
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
	struct interface_policy	*p;
	int			 newstate = 1;

	log_warnx("set_source_state");

	memcpy(&cpid, imsg->data, sizeof(cpid));

	LIST_FOREACH(p, &engine_conf->policy_list, entry) {
		if (p->ifindex != cpid.ifindex && cpid.ifindex != 0)
			continue;
		if (cpid.source < 0) {
			cpid.source = -cpid.source;
			newstate = 0;
		}
		switch (cpid.source) {
		case RTP_PROPOSAL_DHCLIENT:
			p->dhclient = newstate;
			break;
		case RTP_PROPOSAL_SLAAC:
			p->slaac = newstate;
			break;
		case RTP_PROPOSAL_STATIC:
			p->statik = newstate;
			break;
		default:
			break;
		}
	}
}
