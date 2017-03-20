/*	$OpenBSD$	*/

/*
 * Copyright (c) 2017 Kenneth R Westerback <krw@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "netcfgd.h"
#include "frontend.h"
#include "engine.h"
#include "control.h"

__dead void	usage(void);
__dead void	main_shutdown(void);

void	main_sig_handler(int, short, void *);

static pid_t	start_child(int, char *, int, int, int, char *);

void	main_dispatch_frontend(int, short, void *);
void	main_dispatch_engine(int, short, void *);

static int	main_imsg_send_ipc_sockets(struct imsgbuf *, struct imsgbuf *);
static int	main_imsg_send_config(struct netcfgd_conf *);

int	main_reload(void);
int	main_sendboth(enum imsg_type, void *, uint16_t);
void	main_showinfo_ctl(struct imsg *);

void	netcfgd_resolv_conf(const char *);

struct netcfgd_conf	*main_conf;
struct imsgev		*iev_frontend;
struct imsgev		*iev_engine;
char			*conffile;
char			*csock;

pid_t	 frontend_pid;
pid_t	 engine_pid;

uint32_t cmd_opts;

void
main_sig_handler(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
	case SIGHUP:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_debug("configuration reloaded");
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event	 ev_sigint, ev_sigterm, ev_sighup;
	int		 ch;
	int		 debug = 0, engine_flag = 0, frontend_flag = 0;
	char		*saved_argv0;
	int		 pipe_main2frontend[2];
	int		 pipe_main2engine[2];

	conffile = NETCFGD_CONF_FILE;
	csock = NETCFGD_SOCKET;

	log_init(1, LOG_DAEMON);	/* Log to stderr until daemonized. */
	log_setverbose(1);

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = "netcfgd";

	while ((ch = getopt(argc, argv, "dEFf:ns:v")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'E':
			engine_flag = 1;
			break;
		case 'F':
			frontend_flag = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			cmd_opts |= OPT_NOACTION;
			break;
		case 's':
			csock = optarg;
			break;
		case 'v':
			if (cmd_opts & OPT_VERBOSE)
				cmd_opts |= OPT_VERBOSE2;
			cmd_opts |= OPT_VERBOSE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || (engine_flag && frontend_flag))
		usage();

	if (engine_flag)
		engine(debug, cmd_opts & OPT_VERBOSE);
	else if (frontend_flag)
		frontend(debug, cmd_opts & OPT_VERBOSE, csock);

	/* Parse the conf file. */
	if ((main_conf = parse_config(conffile)) == NULL) {
		exit(1);
	}

	if (cmd_opts & OPT_NOACTION) {
		if (cmd_opts & OPT_VERBOSE)
			print_config(main_conf);
		else
			fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	/* Check for root privileges. */
	if (geteuid())
		errx(1, "need root privileges");

	/* Check for assigned daemon user */
	if (getpwnam(NETCFGD_USER) == NULL)
		errx(1, "unknown user %s", NETCFGD_USER);

	log_init(debug, LOG_DAEMON);
	log_setverbose(cmd_opts & OPT_VERBOSE);

	if (!debug)
		daemon(1, 0);

	log_info("startup");

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2frontend) == -1)
		fatal("main2frontend socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2engine) == -1)
		fatal("main2engine socketpair");

	/* Start children. */
	engine_pid = start_child(PROC_ENGINE, saved_argv0, pipe_main2engine[1],
	    debug, cmd_opts & OPT_VERBOSE, NULL);
	frontend_pid = start_child(PROC_FRONTEND, saved_argv0,
	    pipe_main2frontend[1], debug, cmd_opts & OPT_VERBOSE, csock);

	netcfgd_process = PROC_MAIN;
	setproctitle(log_procnames[netcfgd_process]);
	log_procinit(log_procnames[netcfgd_process]);

	event_init();

	/* Setup signal handler. */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* Setup pipes to children. */
	if ((iev_frontend = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_engine = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_frontend->ibuf, pipe_main2frontend[0]);
	iev_frontend->handler = main_dispatch_frontend;
	imsg_init(&iev_engine->ibuf, pipe_main2engine[0]);
	iev_engine->handler = main_dispatch_engine;

	/* Setup event handlers for pipes to engine & frontend. */
	iev_frontend->events = EV_READ;
	event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
	    iev_frontend->events, iev_frontend->handler, iev_frontend);
	event_add(&iev_frontend->ev, NULL);

	iev_engine->events = EV_READ;
	event_set(&iev_engine->ev, iev_engine->ibuf.fd, iev_engine->events,
	    iev_engine->handler, iev_engine);
	event_add(&iev_engine->ev, NULL);

	if (main_imsg_send_ipc_sockets(&iev_frontend->ibuf, &iev_engine->ibuf))
		fatal("could not establish imsg links");
	main_imsg_send_config(main_conf);

	if (kr_init() == -1)
		fatalx("kr_init failed");

#if 0
	if (pledge("rpath stdio sendfd", NULL) == -1)
		fatal("pledge");
#endif

	event_dispatch();

	main_shutdown();
	return (0);
}

__dead void
main_shutdown(void)
{
	pid_t	 pid;
	int	 status;

	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_engine->ibuf.w);
	close(iev_engine->ibuf.fd);

	config_clear(main_conf);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    (pid == engine_pid) ? "engine" :
			    "frontend", WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_frontend);
	free(iev_engine);

	control_cleanup(csock);

	log_info("terminating");
	exit(0);
}

static pid_t
start_child(int p, char *argv0, int fd, int debug, int verbose, char *sockname)
{
	char	*argv[7];
	int	 argc = 0;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (dup2(fd, 3) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_ENGINE:
		argv[argc++] = "-E";
		break;
	case PROC_FRONTEND:
		argv[argc++] = "-F";
		break;
	}
	if (debug)
		argv[argc++] = "-d";
	if (verbose)
		argv[argc++] = "-v";
	if (sockname) {
		argv[argc++] = "-s";
		argv[argc++] = sockname;
	}
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

void
main_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0, verbose;

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
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_RELOAD:
			if (main_reload() == -1)
				log_warnx("configuration reload failed");
			else
				log_warnx("configuration reloaded");
			break;
		case IMSG_CTL_LOG_LEVEL:
			/* Already checked by frontend. */
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			break;
		case IMSG_CTL_SHOW_MAIN_INFO:
			main_showinfo_ctl(&imsg);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
main_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf  *ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0;

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
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_SUPERSEDE_PROPOSAL:
			netcfgd_supersede_proposal(&imsg);
			break;
		case IMSG_DELETE_V4ADDRESS:
			netcfgd_delete_v4address(&imsg);
			break;
		case IMSG_DELETE_V6ADDRESS:
			netcfgd_delete_v6address(&imsg);
			break;
		case IMSG_ADD_V4ADDRESS:
			netcfgd_add_v4address(&imsg);
			break;
		case IMSG_ADD_V6ADDRESS:
			netcfgd_add_v6address(&imsg);
			break;
		case IMSG_DELETE_V4ROUTE:
			netcfgd_delete_v4route(&imsg);
			break;
		case IMSG_DELETE_V6ROUTE:
			netcfgd_delete_v6route(&imsg);
			break;
		case IMSG_ADD_V4ROUTE:
			netcfgd_add_v4route(&imsg);
			break;
		case IMSG_ADD_V6ROUTE:
			netcfgd_add_v6route(&imsg);
			break;
		case IMSG_RESOLV_CONF:
			netcfgd_resolv_conf(imsg.data);
			break;
		case IMSG_SET_MTU:
			netcfgd_set_mtu(&imsg);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
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
main_imsg_compose_frontend(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_frontend)
		imsg_compose_event(iev_frontend, type, 0, pid, -1, data,
		    datalen);
}

void
main_imsg_compose_engine(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_engine)
		imsg_compose_event(iev_engine, type, 0, pid, -1, data,
		    datalen);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen)) != -1)
		imsg_event_add(iev);

	return (ret);
}

static int
main_imsg_send_ipc_sockets(struct imsgbuf *frontend_buf,
    struct imsgbuf *engine_buf)
{
	int pipe_frontend2engine[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_frontend2engine) == -1)
		return (-1);

	if (imsg_compose(frontend_buf, IMSG_SOCKET_IPC, 0, 0,
	    pipe_frontend2engine[0], NULL, 0) == -1)
		return (-1);
	if (imsg_compose(engine_buf, IMSG_SOCKET_IPC, 0, 0,
	    pipe_frontend2engine[1], NULL, 0) == -1)
		return (-1);

	return (0);
}

int
main_reload(void)
{
	struct netcfgd_conf *xconf;

	if ((xconf = parse_config(conffile)) == NULL)
		return (-1);

	if (main_imsg_send_config(xconf) == -1)
		return (-1);

	merge_config(main_conf, xconf);

	return (0);
}

int
main_imsg_send_config(struct netcfgd_conf *xconf)
{
	struct interface	 *ifp;

	/* Send fixed part of config to children. */
	if (main_sendboth(IMSG_RECONF_CONF, xconf, sizeof(*xconf)) == -1)
		return (-1);

	/* Send the group list to children. */
	LIST_FOREACH(ifp, &xconf->interface_list, entry) {
		if (main_sendboth(IMSG_RECONF_INTERFACE, ifp,
			    sizeof(*ifp)) == -1)
			return (-1);
	}

	/* Tell children the revised config is now complete. */
	if (main_sendboth(IMSG_RECONF_END, NULL, 0) == -1)
		return (-1);

	return (0);
}

int
main_sendboth(enum imsg_type type, void *buf, uint16_t len)
{
	if (imsg_compose_event(iev_frontend, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	if (imsg_compose_event(iev_engine, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	return (0);
}

void
main_showinfo_ctl(struct imsg *imsg)
{
	struct ctl_main_info cmi;
	size_t n;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_MAIN_INFO:
		memset(cmi.text, 0, sizeof(cmi.text));
		n = strlcpy(cmi.text, "I'm a little teapot.",
		    sizeof(cmi.text));
		if (n >= sizeof(cmi.text))
			log_debug("%s: I was cut off!", __func__);
		main_imsg_compose_frontend(IMSG_CTL_SHOW_MAIN_INFO,
		    imsg->hdr.pid, &cmi, sizeof(cmi));
		memset(cmi.text, 0, sizeof(cmi.text));
		n = strlcpy(cmi.text, "Full of sencha.",
		    sizeof(cmi.text));
		if (n >= sizeof(cmi.text))
			log_debug("%s: I was cut off!", __func__);
		main_imsg_compose_frontend(IMSG_CTL_SHOW_MAIN_INFO,
		    imsg->hdr.pid, &cmi, sizeof(cmi));
		main_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

void
merge_config(struct netcfgd_conf *conf, struct netcfgd_conf *xconf)
{
	struct interface	*ifp, *nifp;

	/* Remove & discard existing interfaces. */
	while ((ifp = LIST_FIRST(&conf->interface_list)) != NULL) {
		LIST_REMOVE(ifp, entry);
		free(ifp);
	}

	/* Add new interfaces. */
	while ((ifp = LIST_FIRST(&xconf->interface_list)) != NULL) {
		LIST_REMOVE(ifp, entry);
		if (LIST_EMPTY(&conf->interface_list)) {
			LIST_INSERT_HEAD(&conf->interface_list, ifp, entry);
		} else {
			/*
			 * Insert interface before the entry with higher
			 * priority or at the end of the list.
			 */
			LIST_FOREACH(nifp, &conf->interface_list, entry) {
				if (nifp->priority > ifp->priority) {
					LIST_INSERT_BEFORE(nifp, ifp, entry);
					break;
				} else if (LIST_NEXT(nifp, entry) == NULL) {
					LIST_INSERT_AFTER(nifp, ifp, entry);
					break;
				}
			}
		}
	}

	free(xconf);
}

struct netcfgd_conf *
config_new_empty(void)
{
	struct netcfgd_conf	*xconf;

	xconf = calloc(1, sizeof(*xconf));
	if (xconf == NULL)
		fatal(NULL);

	LIST_INIT(&xconf->interface_list);

	return (xconf);
}

void
config_clear(struct netcfgd_conf *conf)
{
	struct netcfgd_conf	*xconf;

	/* Merge current config with an empty config. */
	xconf = config_new_empty();
	merge_config(conf, xconf);

	free(conf);
}

void
netcfgd_supersede_proposal(struct imsg *imsg)
{
	struct rt_msghdr		rtm;
	struct imsg_supersede_proposal	sp;
	ssize_t				rlen;

	memset(&rtm, 0, sizeof(rtm));
	memcpy(&sp, imsg->data, sizeof(sp));

	/* Supersede proposal. */
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_msglen = sizeof(rtm);
	rtm.rtm_flags = RTF_PROTO2;
	rtm.rtm_type = RTM_PROPOSAL;

	rtm.rtm_index = sp.index;
	rtm.rtm_priority = sp.source;
	rtm.rtm_seq = sp.xid;
	rtm.rtm_tableid = sp.rdomain;

	rlen = write(kr_state.route_fd, &rtm, rtm.rtm_msglen);
	if (rlen == -1)
		log_warn("v4_supersede_proposal %0x", sp.xid);
	else if (rlen < (int)rtm.rtm_msglen)
		log_warnx("v4_supersede_proposal short write (%zd < %u)",
		    rlen, rtm.rtm_msglen);
}

void
netcfgd_set_mtu(struct imsg *imsg)
{
	char			 ifname[IF_NAMESIZE];
	struct imsg_set_mtu	 sm;
	struct ifreq		 ifr;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(&sm, imsg->data, sizeof(sm));

	if (if_indextoname(sm.index, ifname) == NULL) {
		log_warnx("invalid interface index %d", sm.index);
		return;
	}
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	ifr.ifr_mtu = sm.mtu;

	if (ioctl(kr_state.inet_fd, SIOCSIFMTU, &ifr) == -1)
		log_warn("SIOCSIFMTU (%d)", sm.mtu);
}

void netcfgd_resolv_conf(const char *contents)
{
	struct stat	 sb;
	FILE		*fp;
	char		*resolv_tail;
	ssize_t		 tailn;
	int		 tailfd;

	fp = fopen("/etc/resolv.conf", "w");
	if (fp == NULL) {
		log_warn("/etc/resolv.conf");
		return;
	}

	fprintf(fp, "%s", contents);

	tailfd = open("/etc/resolv.conf.tail", O_RDONLY);
	if (tailfd == -1) {
		if (errno != ENOENT)
			log_warn("resolv.conf.tail");
		goto done;
	}

	if (fstat(tailfd, &sb) == -1) {
		log_warn("resolv.conf.tail");
		goto done;
	}

	if (sb.st_size >= SSIZE_MAX) {
		log_warnx("resolv.conf.tail too long");
		goto done;
	}

	if (sb.st_size == 0)
		goto done;

	resolv_tail = malloc(sb.st_size);
	if (resolv_tail == NULL) {
		log_warnx("no memory for resolv.conf.tail contents");
		goto done;
	}

	tailn = read(tailfd, resolv_tail, sb.st_size);
	if (tailn == -1)
		log_warn("resolv.conf.tail");
	else if (tailn == 0)
		log_warnx("resolv.conf.tail: empty");
	else if (tailn != sb.st_size)
		log_warnx("resolv.conf.tail: short");
	else
		fprintf(fp, "%.*s", (int)tailn, resolv_tail);

done:
	close(tailfd);
	fclose(fp);
}
