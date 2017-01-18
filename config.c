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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <event.h>
#include <fcntl.h>
#include <util.h>
#include <errno.h>
#include <imsg.h>

#include "proc.h"
#include "newd.h"

int
config_init(struct newd *env)
{
	struct privsep	*ps = &env->newd_ps;
	unsigned int	 what;

	/* Global configuration */
	ps->ps_what[PROC_PARENT] = CONFIG_ALL;
	ps->ps_what[PROC_ENGINE] = CONFIG_VMS;

	/* Other configuration */
	what = ps->ps_what[privsep_process];

	return (0);
}

void
config_purge(struct newd *env, unsigned int reset)
{
	struct privsep		*ps = &env->newd_ps;
	unsigned int		 what;

	what = ps->ps_what[privsep_process] & reset;
}

int
config_setreset(struct newd *env, unsigned int reset)
{
	struct privsep	*ps = &env->newd_ps;
	unsigned int	 id;

	for (id = 0; id < PROC_MAX; id++) {
		if ((reset & ps->ps_what[id]) == 0 ||
		    id == privsep_process)
			continue;
		proc_compose(ps, id, IMSG_CTL_RESET, &reset, sizeof(reset));
	}

	return (0);
}

int
config_getreset(struct newd *env, struct imsg *imsg)
{
	unsigned int	 mode;

	IMSG_SIZE_CHECK(imsg, &mode);
	memcpy(&mode, imsg->data, sizeof(mode));

	config_purge(env, mode);

	return (0);
}

int
config_setvm(struct privsep *ps, struct vmd_vm *vm, uint32_t peerid)
{
	int			 fd = -1;
	int			 kernfd = -1;
	int			 saved_errno = 0;

	errno = 0;

	proc_compose_imsg(ps, PROC_ENGINE, -1,
	    IMSG_NEWDOP_START_GROUP_END, 42, fd,  NULL, 0);

	return (0);

	log_warnx("%s: failed to start vm radishes", __func__);

	if (kernfd != -1)
		close(kernfd);

	errno = saved_errno;
	if (errno == 0)
		errno = EINVAL;
	return (-1);
}

int
config_getvm(struct privsep *ps, struct imsg *imsg)
{
	struct vmd_vm			*vm;

	IMSG_SIZE_CHECK(imsg, &vm);
	memcpy(&vm, imsg->data, sizeof(vm));

	errno = 0;
	if (-1)
		goto fail;

	return (0);

 fail:
	if (imsg->fd != -1) {
		close(imsg->fd);
		imsg->fd = -1;
	}

	if (errno == 0)
		errno = EINVAL;

	return (-1);
}
