/*	$OpenBSD$	*/

/*
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

#define CONF_FILE		"/etc/netcfgd.conf"
#define	NETCFGD_SOCKET		"/var/run/netcfgd.sock"
#define NETCFGD_USER		"_netcfgd"

#define OPT_VERBOSE	0x00000001
#define OPT_VERBOSE2	0x00000002
#define OPT_NOACTION	0x00000004

#define NETCFGD_MAXTEXT		256
#define NETCFGD_MAXGROUPNAME	16
#define	NETCFGD_MAX_RTSOCK_BUF	128 * 1024
#define NETCFGD_RT_BUF_SIZE	16384

static const char * const log_procnames[] = {
	"main",
	"frontend",
	"engine"
};

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_LOG_VERBOSE,
	IMSG_CTL_RELOAD,
	IMSG_CTL_SHOW_ENGINE_INFO,
	IMSG_CTL_SHOW_FRONTEND_INFO,
	IMSG_CTL_SHOW_MAIN_INFO,
	IMSG_CTL_END,
	IMSG_RECONF_CONF,
	IMSG_RECONF_GROUP,
	IMSG_RECONF_END,
	IMSG_SOCKET_IPC,
	IMSG_SEND_PROPOSAL
};

enum {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND
} netcfgd_process;

struct group {
	LIST_ENTRY(group)	 entry;
	char		name[NETCFGD_MAXGROUPNAME];
	int		yesno;
	int		integer;
	int		group_v4_bits;
	int		group_v6_bits;
	struct in_addr	group_v4address;
	struct in6_addr	group_v6address;
};

struct netcfgd_conf {
	int		yesno;
	int		integer;
	char		global_text[NETCFGD_MAXTEXT];
	LIST_HEAD(, group)	group_list;
};

struct ctl_frontend_info {
	int		yesno;
	int		integer;
	char		global_text[NETCFGD_MAXTEXT];
};

struct ctl_engine_info {
	char		name[NETCFGD_MAXGROUPNAME];
	int		yesno;
	int		integer;
	int		group_v4_bits;
	int		group_v6_bits;
	struct in_addr	group_v4address;
	struct in6_addr	group_v6address;
};

struct ctl_main_info {
	char		text[NETCFGD_MAXTEXT];
};

struct imsg_proposal {
	uint8_t		rtstatic[128];
	uint8_t		rtsearch[128];
	struct in_addr	gateway;
	struct in_addr	ifa;
	struct in_addr	mask;
	struct in_addr	dns1;
	struct in_addr	dns2;
	struct in_addr	dns3;
	struct in_addr	dns4;
	int		xid;
	int		index;
	int		mtu;
	int		addrs;
	int		inits;
	int		flags;
	int		rtsearch_encoded;
};

extern uint32_t	 cmd_opts;
extern char	*csock;

/* netcfgd.c */
void	main_imsg_compose_frontend(int, pid_t, void *, uint16_t);
void	main_imsg_compose_engine(int, pid_t, void *, uint16_t);
void	merge_config(struct netcfgd_conf *, struct netcfgd_conf *);
void	imsg_event_add(struct imsgev *);
int	imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
	    int, void *, uint16_t);

struct netcfgd_conf       *config_new_empty(void);
void			config_clear(struct netcfgd_conf *);

/* printconf.c */
void	print_config(struct netcfgd_conf *);

/* parse.y */
struct netcfgd_conf	*parse_config(char *);
int			 cmdline_symset(char *);

/* kroute.c */
int	kr_init(void);
