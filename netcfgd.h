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

#define NETCFGD_CONF_FILE	"/etc/netcfgd.conf"
#define NETCFGD_SOCKET		"/var/run/netcfgd.sock"
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
	IMSG_CTL_DISCARD_PROPOSAL,
	IMSG_CTL_SHOW_PROPOSALS,
	IMSG_CTL_REPLY_V4PROPOSAL,
	IMSG_CTL_REPLY_V6PROPOSAL,
	IMSG_CTL_SHOW_FRONTEND_INFO,
	IMSG_CTL_SHOW_MAIN_INFO,
	IMSG_CTL_SET_SOURCE_STATE,
	IMSG_CTL_END,
	IMSG_RECONF_CONF,
	IMSG_RECONF_INTERFACE,
	IMSG_RECONF_END,
	IMSG_SOCKET_IPC,
	IMSG_SEND_V4PROPOSAL,
	IMSG_SUPERSEDE_PROPOSAL,
	IMSG_SEND_V6PROPOSAL,
	IMSG_DELETE_V4ADDRESS,
	IMSG_DELETE_V6ADDRESS,
	IMSG_ADD_V4ADDRESS,
	IMSG_ADD_V6ADDRESS,
	IMSG_DELETE_V4ROUTE,
	IMSG_DELETE_V6ROUTE,
	IMSG_ADD_V4ROUTE,
	IMSG_ADD_V6ROUTE,
	IMSG_SET_MTU,
	IMSG_RESOLV_CONF
};

enum {
	PROC_MAIN,
	PROC_ENGINE,
	PROC_FRONTEND
} netcfgd_process;

struct interface {
	LIST_ENTRY(interface)	 entry;

	char			 name[IF_NAMESIZE];
	unsigned int		 ifindex;
	int			 dhclient_ok;
	int			 slaac_ok;
	int			 v4static_ok;
	int			 v6static_ok;
	int			 priority;
	struct imsg_v4proposal	*dhclient;
	struct imsg_v4proposal	*v4static;
	struct imsg_v6proposal	*slaac;
	struct imsg_v6proposal	*v6static;
};

struct netcfgd_conf {
	LIST_HEAD(, interface)	interface_list;
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
	uint8_t		rtstatic[RTSTATIC_LEN];
	uint8_t		rtsearch[RTSEARCH_LEN];
	uint8_t		rtdns[RTDNS_LEN];
	struct in_addr	ifa;
	struct in_addr	netmask;
	unsigned int	rtstatic_len;
	unsigned int	rtsearch_len;
	unsigned int	rtdns_len;
	int		xid;
	unsigned int	index;
	int		rdomain;
	int		source;
	int		mtu;
	int		addrs;
	int		inits;
	int		kill;
};

struct imsg_v6proposal {
	uint8_t		rtstatic[RTSTATIC_LEN];
	uint8_t		rtsearch[RTSEARCH_LEN];
	uint8_t		rtdns[RTDNS_LEN];
	struct in6_addr	ifa;
	struct in6_addr	netmask;
	unsigned int	rtstatic_len;
	unsigned int	rtsearch_len;
	unsigned int	rtdns_len;
	int		xid;
	unsigned int	index;
	int		rdomain;
	int		source;
	int		mtu;
	int		addrs;
	int		inits;
	int		kill;
};

struct imsg_supersede_proposal {
	unsigned int	index;
	int		source;
	int		xid;
	int		rdomain;
};

struct imsg_delete_v4address {
	struct in_addr		addr;
	unsigned int		index;
};
struct imsg_delete_v6address {
	struct in6_addr		addr;
	unsigned int		index;
};
struct imsg_add_v4address {
	struct in_addr		addr;
	struct in_addr		netmask;
	unsigned int		index;
};
struct imsg_add_v6address {
	struct in6_addr		addr;
	struct in6_addr		netmask;
	unsigned int		index;
};
struct imsg_delete_v4route {
	struct in_addr		dest;
	struct in_addr		netmask;
	struct in_addr		gateway;
	int			index;
	int			rdomain;
};
struct imsg_delete_v6route {
	struct in6_addr		dest;
	struct in6_addr		netmask;
	struct in6_addr		gateway;
	struct in_addr		ifa;
	int			index;
	int			rdomain;
	int			addrs;
	int			flags;
};
struct imsg_add_v4route {
	struct in_addr		dest;
	struct in_addr		netmask;
	struct in_addr		gateway;
	struct in_addr		ifa;
	int			index;
	int			rdomain;
	int			addrs;
	int			flags;
};
struct imsg_add_v6route {
	struct in6_addr		dest;
	struct in6_addr		netmask;
	struct in6_addr		gateway;
};
struct imsg_set_mtu {
	int			mtu;
	unsigned int		index;
};

extern uint32_t	 cmd_opts;

/* netcfgd.c */
void	main_imsg_compose_frontend(int, pid_t, void *, uint16_t);
void	main_imsg_compose_engine(int, pid_t, void *, uint16_t);
void	merge_config(struct netcfgd_conf *, struct netcfgd_conf *);
void	imsg_event_add(struct imsgev *);
int	imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
	    int, void *, uint16_t);
void	netcfgd_supersede_proposal(struct imsg *);
void	netcfgd_set_mtu(struct imsg *);

struct netcfgd_conf	*config_new_empty(void);
void			 config_clear(struct netcfgd_conf *);

/* printconf.c */
void	print_config(struct netcfgd_conf *);

/* parse.y */
struct netcfgd_conf	*parse_config(char *);
int			 cmdline_symset(char *);

/* kroute.c */
struct kr_state {
	pid_t			pid;
	int			route_fd;
	int			inet_fd;
	struct event		ev;
};
extern struct kr_state	kr_state;

int	kr_init(void);
int	kr_get_rtaddrs(int, struct sockaddr *, struct sockaddr **);

/* netcfgd_v4.c	*/
void	netcfgd_delete_v4route(struct imsg *);
void	netcfgd_add_v4route(struct imsg *);
void	netcfgd_delete_v4address(struct imsg *);
void	netcfgd_add_v4address(struct imsg *);

/* netcfgd_v6.c	*/
void	netcfgd_delete_v6route(struct imsg *);
void	netcfgd_add_v6route(struct imsg *);
void	netcfgd_delete_v6address(struct imsg *);
void	netcfgd_add_v6address(struct imsg *);
