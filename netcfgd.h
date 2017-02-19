/*	$OpenBSD$	*/

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

#define CONF_FILE		"/etc/netcfgd.conf"
#define	NETCFGD_SOCKET		"/var/run/netcfgd.sock"
#define NETCFGD_USER		"_netcfgd"

#define OPT_VERBOSE	0x00000001
#define OPT_VERBOSE2	0x00000002
#define OPT_NOACTION	0x00000004

#define NETCFGD_MAXTEXT		256
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
	IMSG_CTL_LOG_LEVEL,
	IMSG_CTL_RELOAD,
	IMSG_CTL_KILL_PROPOSAL,
	IMSG_CTL_SHOW_PROPOSALS,
	IMSG_CTL_REPLY_V4PROPOSAL,
	IMSG_CTL_REPLY_V6PROPOSAL,
	IMSG_CTL_SHOW_FRONTEND_INFO,
	IMSG_CTL_SHOW_MAIN_INFO,
	IMSG_CTL_SET_SOURCE_STATE,
	IMSG_CTL_END,
	IMSG_RECONF_CONF,
	IMSG_RECONF_POLICY,
	IMSG_RECONF_END,
	IMSG_SOCKET_IPC,
	IMSG_SEND_V4PROPOSAL,
	IMSG_SEND_V6PROPOSAL,
	IMSG_EXECUTE_V4PROPOSAL,
	IMSG_EXECUTE_V6PROPOSAL
};

enum {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND
} netcfgd_process;

struct interface_policy {
	LIST_ENTRY(interface_policy)	 entry;

	char		name[IF_NAMESIZE];
	unsigned int	ifindex;
	int		dhclient;
	int		slaac;
	int		statik;
};

struct netcfgd_conf {
	LIST_HEAD(, interface_policy)	policy_list;
};

struct ctl_frontend_info {
	int		yesno;
	int		integer;
	char		global_text[NETCFGD_MAXTEXT];
};

struct ctl_main_info {
	char		text[NETCFGD_MAXTEXT];
};

struct ctl_policy_id {
	unsigned int	ifindex;
	int		source;
};

struct imsg_v4proposal {
	uint8_t		rtstatic[128];
	uint8_t		rtsearch[128];
	struct in_addr	gateway;
	struct in_addr	ifa;
	struct in_addr	netmask;
	struct in_addr	dns1;
	struct in_addr	dns2;
	struct in_addr	dns3;
	struct in_addr	dns4;
	int		xid;
	unsigned int	index;
	int		source;
	int		mtu;
	int		addrs;
	int		inits;
	int		flags;
	int		rtsearch_encoded;
};

struct imsg_v6proposal {
	uint8_t		rtstatic[128];
	uint8_t		rtsearch[128];
	struct in6_addr	gateway;
	struct in6_addr	ifa;
	struct in6_addr	netmask;
	struct in6_addr	dns1;
	struct in6_addr	dns2;
	struct in6_addr	dns3;
	struct in6_addr	dns4;
	int		xid;
	unsigned int	index;
	int		source;
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

/* v4.c	*/
void	v4_execute_proposal(struct imsg *);

/* v6.c	*/
void	v6_execute_proposal(struct imsg *);
