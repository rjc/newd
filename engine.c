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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <net/if.h>
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
void		 engine_process_v4proposal(struct imsg_v4proposal *);
void		 engine_process_v6proposal(struct imsg_v6proposal *);
void		 engine_kill_proposal(int);
void		 engine_show_v4proposal(struct imsg *,
		     struct imsg_v4proposal *, struct ctl_show_proposal *);
void		 engine_show_v6proposal(struct imsg *,
		     struct imsg_v6proposal *, struct ctl_show_proposal *);

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
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;

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

void
engine_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0, payload;

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
			/* Already checked by frontend. */
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
	struct group			*g;
	struct imsgev			*iev = bula;
	struct imsgbuf			*ibuf;
	struct imsg_v4proposal		*p4;
	struct imsg_v6proposal		*p6;
	ssize_t				 n;
	int				 shut = 0;

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
			LIST_INIT(&nconf->group_list);
			break;
		case IMSG_RECONF_GROUP:
			if ((g = malloc(sizeof(struct group))) == NULL)
				fatal(NULL);
			memcpy(g, imsg.data, sizeof(struct group));
			LIST_INSERT_HEAD(&nconf->group_list, g, entry);
			break;
		case IMSG_RECONF_END:
			merge_config(engine_conf, nconf);
			nconf = NULL;
			break;
		case IMSG_SEND_V4PROPOSAL:
			if ((p4 = malloc(sizeof(struct imsg_v4proposal))) ==
			    NULL)
				fatal(NULL);
			memcpy(p4, imsg.data, sizeof(struct imsg_v4proposal));
			engine_process_v4proposal(p4);
			break;
		case IMSG_SEND_V6PROPOSAL:
			if ((p6 = malloc(sizeof(struct imsg_v6proposal))) ==
			    NULL)
				fatal(NULL);
			memcpy(p6, imsg.data, sizeof(struct imsg_v6proposal));
			engine_process_v6proposal(p6);
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
	struct ctl_show_proposal	 csp;
	struct proposal_entry		*p;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_PROPOSALS:
		memcpy(&csp, imsg->data, sizeof(csp));
		TAILQ_FOREACH(p, &proposal_queue, entry) {
			if (p->v4proposal != NULL)
				engine_show_v4proposal(imsg, p->v4proposal,
				    &csp);
			else if (p->v6proposal != NULL)
				engine_show_v6proposal(imsg, p->v6proposal,
				    &csp);
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
engine_process_v4proposal(struct imsg_v4proposal *imsg)
{
	struct proposal_entry	*p;

	/* Discard duplicate proposals. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if (p->v4proposal->xid == imsg->xid) {
			free(imsg);
			log_warnx("proposal already received");
			return;
		}
	}

	/* Discard superseded proposals. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if ((p->v4proposal->index == imsg->index) &&
		    (p->v4proposal->source == imsg->source)) {
			log_warnx("proposal being superseded");
			break;
		}
	}

	/* Remove superseded proposal. */
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
	p->v4proposal = imsg;

	TAILQ_INSERT_HEAD(&proposal_queue, p, entry);
}

void
engine_process_v6proposal(struct imsg_v6proposal *imsg)
{
	struct proposal_entry	*p;

	/* Discard duplicate proposals. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if (p->v4proposal->xid == imsg->xid) {
			free(imsg);
			log_warnx("proposal already received");
			return;
		}
	}

	/* Discard superseded proposals. */
	TAILQ_FOREACH(p, &proposal_queue, entry) {
		if ((p->v6proposal->index == imsg->index) &&
		    (p->v6proposal->source == imsg->source)) {
			log_warnx("proposal being superseded");
			break;
		}
	}

	/* Remove superseded proposal. */
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
	p->v6proposal = imsg;

	TAILQ_INSERT_HEAD(&proposal_queue, p, entry);
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
    struct ctl_show_proposal *csp)
{
	struct imsg_v4proposal	imsg_v4proposal;

	if (csp->ifindex != 0 && p->index != csp->ifindex)
		return;
	if (csp->source != 0 && csp->source != p->source)
		return;

	memcpy(&imsg_v4proposal, p, sizeof(imsg_v4proposal));
	engine_imsg_compose_frontend(IMSG_CTL_REPLY_V4PROPOSAL, imsg->hdr.pid,
	    &imsg_v4proposal, sizeof(imsg_v4proposal));
}

void
engine_show_v6proposal(struct imsg *imsg, struct imsg_v6proposal *p,
    struct ctl_show_proposal *csp)
{
	struct imsg_v6proposal	imsg_v6proposal;

	if (csp->ifindex != 0 && p->index != csp->ifindex)
		return;
	if (csp->source != 0 && csp->source != p->source)
		return;

	memcpy(&imsg_v6proposal, p, sizeof(imsg_v6proposal));
	engine_imsg_compose_frontend(IMSG_CTL_REPLY_V6PROPOSAL, imsg->hdr.pid,
	    &imsg_v6proposal, sizeof(imsg_v6proposal));
}
