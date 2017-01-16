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
	IMSG_VMDOP_START_VM_REQUEST = IMSG_PROC_MAX,
	IMSG_VMDOP_START_VM_END,
	IMSG_VMDOP_START_VM_RESPONSE,
	IMSG_VMDOP_TERMINATE_VM_REQUEST,
	IMSG_VMDOP_TERMINATE_VM_RESPONSE,
	IMSG_VMDOP_TERMINATE_VM_EVENT,
	IMSG_VMDOP_GET_INFO_VM_REQUEST,
	IMSG_VMDOP_GET_INFO_VM_DATA,
	IMSG_VMDOP_GET_INFO_VM_END_DATA,
	IMSG_VMDOP_LOAD,
	IMSG_VMDOP_RELOAD,
	IMSG_VMDOP_VM_REBOOT
};

struct vmop_result {
	int			 vmr_result;
	uint32_t		 vmr_id;
	pid_t			 vmr_pid;
	char			 vmr_ttyname[16];
};

struct vmd_vm {
	struct imsgev            vm_iev;
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
int	 config_setvm(struct privsep *, struct vmd_vm *, uint32_t);
int	 config_getvm(struct privsep *, struct imsg *);

/* parse.y */
int	 parse_config(const char *);
int	 cmdline_symset(char *);
