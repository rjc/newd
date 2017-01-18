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

#ifdef NEWD_DEBUG
#define dprintf(x...)   do { log_debug(x); } while(0)
#else
#define dprintf(x...)
#endif /* NEWD_DEBUG */

#define NEWD_CONF		"/etc/newd.conf"
#define	NEWD_SOCKET		"/var/run/newd.sock"
#define NEWD_USER		"_newd"

#define NEWD_MAXTEXT		256
#define NEWD_MAXGROUPNAME	16

enum imsg_type {
	IMSG_NEWDOP_GET_INFO_PARENT_REQUEST = IMSG_PROC_MAX,
	IMSG_NEWDOP_GET_INFO_PARENT_DATA,
	IMSG_NEWDOP_GET_INFO_PARENT_END_DATA,
	IMSG_NEWDOP_GET_INFO_ENGINE_REQUEST,
	IMSG_NEWDOP_GET_INFO_ENGINE_DATA,
	IMSG_NEWDOP_GET_INFO_ENGINE_END_DATA,
	IMSG_NEWDOP_GET_INFO_CONTROL_REQUEST,
	IMSG_NEWDOP_GET_INFO_CONTROL_DATA,
	IMSG_NEWDOP_GET_INFO_CONTROL_END_DATA,
	IMSG_NEWDOP_LOAD,
	IMSG_NEWDOP_RELOAD
};

struct newd_control_info {
	int		yesno;
	int		integer;
	char		global_text[NEWD_MAXTEXT];
};

struct newd_engine_info {
	char		name[NEWD_MAXGROUPNAME];
	int		yesno;
	int		integer;
	int		group_v4_bits;
	int		group_v6_bits;
	struct in_addr	group_v4address;
	struct in6_addr	group_v6address;
};

struct newd_parent_info {
	char		text[NEWD_MAXTEXT];
};

struct group {
	LIST_ENTRY(group)	 entry;
	char		newd_group_name[NEWD_MAXGROUPNAME];
	int		newd_group_yesno;
	int		newd_group_integer;
	int		newd_group_v4_bits;
	int		newd_group_v6_bits;
	struct in_addr	newd_group_v4address;
	struct in6_addr	newd_group_v6address;
};

struct newd {
	struct privsep		 newd_ps;
	const char		*newd_conffile;

	int			 newd_debug;
	int			 newd_verbose;
	int			 newd_noaction;

	int			 newd_yesno;
	int			 newd_integer;
	char			 newd_global_text[NEWD_MAXTEXT];
	LIST_HEAD(, group)	 newd_group_list;
};

/* newd.c */
void	 newd_reload(unsigned int, const char *);
char	*get_string(uint8_t *, size_t);

/* engine.c */
void	 engine(struct privsep *, struct privsep_proc *);
void	 engine_shutdown(void);

/* control.c */
int	 config_init(struct newd *);
void	 config_purge(struct newd *, unsigned int);
int	 config_setreset(struct newd *, unsigned int);
int	 config_getreset(struct newd *, struct imsg *);

/* parse.y */
int	 parse_config(const char *);
int	 cmdline_symset(char *);
