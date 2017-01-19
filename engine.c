/*	$OpenBSD$	*/

/*
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
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

#include <sys/param.h>	/* nitems */
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "proc.h"
#include "newd.h"
#include "engine.h"

void engine_sighdlr(int, short, void *);
int engine_dispatch_parent(int, struct privsep_proc *, struct imsg *);
void engine_run(struct privsep *, struct privsep_proc *, void *);
void engine_show_info(struct privsep *, struct imsg *);

extern struct newd *env;

extern char *__progname;

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	engine_dispatch_parent  },
};

void
engine(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), engine_run, NULL);
}

void
engine_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	if (config_init(ps->ps_env) == -1)
		fatal("failed to initialize configuration");

	signal_del(&ps->ps_evsigchld);
	signal_set(&ps->ps_evsigchld, SIGCHLD, engine_sighdlr, ps);
	signal_add(&ps->ps_evsigchld, NULL);

	/*
	 * pledge in the engine process:
	 * stdio - for malloc and basic I/O including events.
	 */
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
}

int
engine_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	int			 res = 0, cmd = 0, verbose;
	unsigned int		 mode;

	switch (imsg->hdr.type) {
	case IMSG_NEWDOP_GET_INFO_ENGINE_REQUEST:
		engine_show_info(ps, imsg);
		cmd = IMSG_NEWDOP_GET_INFO_ENGINE_END_DATA;
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));

		config_getreset(env, imsg);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	case IMSG_NEWDOP_GET_INFO_ENGINE_END_DATA:
		if (proc_compose_imsg(ps, PROC_PARENT, -1, cmd,
		    imsg->hdr.peerid, -1, &mode, sizeof(mode)) == -1)
			return (-1);
		break;
	default:
		if (proc_compose_imsg(ps, PROC_PARENT, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return (-1);
		break;
	}

	return (0);
}

void
engine_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	default:
		fatalx("unexpected signal");
	}
}

/*
 * engine_shutdown
 */
void
engine_shutdown(void)
{
}

void
engine_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[NEWD_MAXGROUPNAME];
	struct newd_engine_info nei;
	struct group *g;

	switch (imsg->hdr.type) {
	case IMSG_NEWDOP_GET_INFO_ENGINE_REQUEST:
		memcpy(filter, imsg->data, sizeof(filter));
		LIST_FOREACH(g, &env->newd_group_list, entry) {
			if (filter[0] == '\0' || memcmp(filter,
			    g->newd_group_name, sizeof(filter)) == 0) {
				memcpy(nei.name, g->newd_group_name,
				    sizeof(nei.name));
				nei.yesno = g->newd_group_yesno;
				nei.integer = g->newd_group_integer;
				nei.verbose = log_getverbose();
				nei.group_v4_bits = g->newd_group_v4_bits;
				nei.group_v6_bits = g->newd_group_v6_bits;
				memcpy(&nei.group_v4address,
				    &g->newd_group_v4address,
				    sizeof(nei.group_v4address));
				memcpy(&nei.group_v6address,
				    &g->newd_group_v6address,
				    sizeof(nei.group_v6address));
			}
			if (proc_compose_imsg(ps, PROC_PARENT, -1,
			    IMSG_NEWDOP_GET_INFO_ENGINE_DATA, imsg->hdr.peerid,
			    -1, &nei, sizeof(nei)) == -1)
				return;
		}
		if (proc_compose_imsg(ps, PROC_PARENT, -1,
		    IMSG_NEWDOP_GET_INFO_ENGINE_END_DATA, imsg->hdr.peerid,
			    -1, &nei, sizeof(nei)) == -1)
				return;
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}
