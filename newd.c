/*	$OpenBSD$	*/

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/cdefs.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <util.h>

#include "proc.h"
#include "newd.h"

__dead void usage(void);

int	 main(int, char **);
int	 newd_configure(struct privsep *);
void	 newd_sighdlr(int sig, short event, void *arg);
void	 newd_shutdown(void);
int	 newd_control_run(void);
int	 newd_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 newd_dispatch_engine(int, struct privsep_proc *, struct imsg *);

void newd_show_info(struct privsep *, struct imsg *);

struct newd	*env;

static struct privsep_proc procs[] = {
	{ "control",	PROC_CONTROL,	newd_dispatch_control, control },
	{ "engine",	PROC_ENGINE,	newd_dispatch_engine, engine,
		engine_shutdown },
};

/* For the privileged process */
static struct privsep_proc *proc_priv = &procs[0];
static struct passwd proc_privpw;

int
newd_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep			*ps = p->p_ps;
	int				 res = 0, cmd = 0, verbose;
	unsigned int			 v = 0;
	char				*str = NULL;

	switch (imsg->hdr.type) {
	case IMSG_NEWDOP_GET_INFO_ENGINE_REQUEST:
		proc_forward_imsg(ps, imsg, PROC_ENGINE, -1);
		break;
	case IMSG_NEWDOP_GET_INFO_PARENT_REQUEST:
		newd_show_info(ps, imsg);
		break;
	case IMSG_NEWDOP_LOAD:
		IMSG_SIZE_CHECK(imsg, str); /* at least one byte for path */
		str = get_string((uint8_t *)imsg->data, IMSG_DATA_SIZE(imsg));
	case IMSG_NEWDOP_RELOAD:
		newd_reload(0, str);
		free(str);
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &v);
		memcpy(&v, imsg->data, sizeof(v));
		newd_reload(v, str);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);

		proc_forward_imsg(ps, imsg, PROC_ENGINE, -1);
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	default:
		if (proc_compose_imsg(ps, PROC_CONTROL, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return (-1);
		break;
	}

	return (0);
}

int
newd_dispatch_engine(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	int			 res = 0;

	switch (imsg->hdr.type) {
	case IMSG_NEWDOP_GET_INFO_ENGINE_DATA:
		proc_forward_imsg(ps, imsg, PROC_CONTROL, -1);
		break;
	case IMSG_NEWDOP_GET_INFO_ENGINE_END_DATA:
		proc_forward_imsg(ps, imsg, PROC_CONTROL, -1);
		break;
	case IMSG_NEWDOP_ADD_GROUP:
		proc_forward_imsg(ps, imsg, PROC_CONTROL, -1);
		break;
	default:
		return (-1);
	}

	return (0);
}

void
newd_sighdlr(int sig, short event, void *arg)
{
	if (privsep_process != PROC_PARENT)
		return;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);

		/*
		 * This is safe because libevent uses async signal handlers
		 * that run in the event loop and not in signal context.
		 */
		newd_reload(0, NULL);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		newd_shutdown();
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-dnv] [-D macro=value] [-f file]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	struct privsep		*ps;
	int			 ch;
	const char		*conffile = NEWD_CONF;
	enum privsep_procid	 proc_id = PROC_PARENT;
	int			 proc_instance = 0;
	const char		*errp, *title = NULL;
	int			 argc0 = argc;

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("calloc: env");

	while ((ch = getopt(argc, argv, "D:P:I:df:vn")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			env->newd_debug = 2;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'v':
			env->newd_verbose++;
			break;
		case 'n':
			env->newd_noaction = 1;
			break;
		case 'P':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'I':
			proc_instance = strtonum(optarg, 0,
			    PROC_MAX_INSTANCES, &errp);
			if (errp)
				fatalx("invalid process instance");
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	if (argc > 0)
		usage();

	if (env->newd_noaction && !env->newd_debug)
		env->newd_debug = 1;

	/* check for root privileges */
	if (env->newd_noaction == 0) {
		if (geteuid())
			fatalx("need root privileges");
	}

	ps = &env->newd_ps;
	ps->ps_env = env;

	if (config_init(env) == -1)
		fatal("failed to initialize configuration");

	if ((ps->ps_pw = getpwnam(NEWD_USER)) == NULL)
		fatal("unknown user %s", NEWD_USER);

	/* First proc runs as root without pledge but in default chroot */
	proc_priv->p_pw = &proc_privpw; /* initialized to all 0 */
	proc_priv->p_chroot = ps->ps_pw->pw_dir; /* from NEWD_USER */

	/* Configure the control socket */
	ps->ps_csock.cs_name = NEWD_SOCKET;
	TAILQ_INIT(&ps->ps_rcsocks);

	/* Configuration will be parsed after forking the children */
	env->newd_conffile = conffile;

	log_init(env->newd_debug, LOG_DAEMON);
	log_setverbose(env->newd_verbose);

	if (env->newd_noaction)
		ps->ps_noaction = 1;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), argc0, argv, proc_id);

	log_procinit("parent");
	if (!env->newd_debug && daemon(0, 0) == -1)
		fatal("can't daemonize");

	if (ps->ps_noaction == 0)
		log_info("startup");

	event_init();

	signal_set(&ps->ps_evsigint, SIGINT, newd_sighdlr, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, newd_sighdlr, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, newd_sighdlr, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, newd_sighdlr, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, newd_sighdlr, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	if (!env->newd_noaction)
		proc_connect(ps);

	if (newd_configure(ps) == -1)
		fatalx("configuration failed");

	event_dispatch();

	log_debug("parent exiting");

	return (0);
}

int
newd_configure(struct privsep *ps)
{
	struct newd_engine_info nei;
	struct group	*g;

	/*
	 * pledge in the parent process:
	 * stdio - for malloc and basic I/O including events.
	 * rpath - for reload to open and read the configuration files.
	 * wpath - for opening disk images and tap devices.
	 * tty - for openpty.
	 * proc - run kill to terminate its children safely.
	 * sendfd - for disks, interfaces and other fds.
	 */
	if (pledge("stdio rpath wpath proc tty sendfd", NULL) == -1)
		fatal("pledge");

	if (parse_config(env->newd_conffile) == -1) {
		proc_kill(&env->newd_ps);
		exit(1);
	}

	if (env->newd_noaction) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(&env->newd_ps);
		exit(0);
	}

	/* Send configured groups to the engine. */
	LIST_FOREACH(g, env->newd_groups, entry) {
		memset(&nei, 0, sizeof(nei));
		nei.yesno = g->newd_group_yesno;
		nei.integer = g->newd_group_integer;
		nei.group_v4_bits = g->newd_group_v4_bits;
		nei.group_v6_bits = g->newd_group_v6_bits;
		memcpy(&nei.name, g->newd_group_name, sizeof(nei.name));
		memcpy(&nei.group_v4address, &g->newd_group_v4address,
		    sizeof(nei.group_v4address));
		memcpy(&nei.group_v6address, &g->newd_group_v6address,
		    sizeof(nei.group_v6address));
		proc_compose(ps, PROC_ENGINE, IMSG_NEWDOP_ADD_GROUP,
		    &nei, sizeof(nei));
	}

	return (0);
}

void
newd_reload(unsigned int reset, const char *filename)
{
	int	reload = 0;

	/* Switch back to the default config file */
	if (filename == NULL || *filename == '\0') {
		filename = env->newd_conffile;
		reload = 1;
	}

	log_debug("%s: level %d config file %s", __func__, reset, filename);

	if (reset) {
		/* Purge the configuration */
		config_purge(env, reset);
		config_setreset(env, reset);
	} else {
		/*
		 * Load or reload the configuration.
		 *
		 * Reloading removes all non-running VMs before processing the
		 * config file, whereas loading only adds to the existing list
		 * of VMs.
		 */

		if (parse_config(filename) == -1) {
			log_debug("%s: failed to load config file %s",
			    __func__, filename);
		}
	}
}

void
newd_shutdown(void)
{
	proc_kill(&env->newd_ps);
	free(env);

	log_warnx("parent terminating");
	exit(0);
}

void
newd_show_info(struct privsep *ps, struct imsg *imsg)
{
	struct newd_parent_info	npi;

	switch (imsg->hdr.type) {
	case IMSG_NEWDOP_GET_INFO_PARENT_REQUEST:
		npi.verbose = log_getverbose();
		memcpy(npi.text, env->newd_global_text, sizeof(npi.text));
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_NEWDOP_GET_INFO_PARENT_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
			return;
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_NEWDOP_GET_INFO_PARENT_END_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
			return;
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

char *
get_string(uint8_t *ptr, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		if (!isprint(ptr[i]))
			break;

	return strndup(ptr, i);
}
