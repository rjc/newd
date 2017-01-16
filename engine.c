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

int engine_pipe(struct vmd_vm *, int, void (*)(int, short, void *));

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
	 * engine - for the engine ioctls and operations.
	 * proc - for forking and maitaining vms.
	 * recvfd - for disks, interfaces and other fds.
	 */
	if (pledge("stdio engine recvfd proc", NULL) == -1)
		fatal("pledge");
}

int
engine_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	int			 res = 0, cmd = 0, verbose;
	struct vmd_vm		*vm;
	struct vmop_result	 vmr;
	uint32_t		 id = 0;
	unsigned int		 mode;

	switch (imsg->hdr.type) {
	case IMSG_VMDOP_START_VM_REQUEST:
		res = config_getvm(ps, imsg);
		if (res == -1) {
			res = errno;
			cmd = IMSG_VMDOP_START_VM_RESPONSE;
		}
		break;
	case IMSG_VMDOP_START_VM_END:
		cmd = IMSG_VMDOP_START_VM_RESPONSE;
		break;
	case IMSG_VMDOP_TERMINATE_VM_REQUEST:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));
		id = 1;

		if ((vm = NULL) != NULL) {
			log_debug("%s: sending shutdown request to vm %d",
			    __func__, id);

			/*
			 * Request reboot but mark the VM as shutting down.
			 * This way we can terminate the VM after the triple
			 * fault instead of reboot and avoid being stuck in
			 * the ACPI-less powerdown ("press any key to reboot")
			 * of the VM.
			 */
			if (imsg_compose_event(&vm->vm_iev,
			    IMSG_VMDOP_VM_REBOOT, 0, 0, -1, NULL, 0) == -1)
				res = errno;
			else
				res = 0;
		} else {
			/* Terminate VMs that are unknown or shutting down */
			res = 0;
		}
		cmd = IMSG_VMDOP_TERMINATE_VM_RESPONSE;
		break;
	case IMSG_VMDOP_GET_INFO_VM_REQUEST:
		res = 0;
		cmd = IMSG_VMDOP_GET_INFO_VM_END_DATA;
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

		/* Forward message to each process */
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	case IMSG_VMDOP_START_VM_RESPONSE:
		if (res != 0) {
		}
	case IMSG_VMDOP_TERMINATE_VM_RESPONSE:
		memset(&vmr, 0, sizeof(vmr));
		vmr.vmr_result = res;
		vmr.vmr_id = id;
		if (proc_compose_imsg(ps, PROC_PARENT, -1, cmd,
		    imsg->hdr.peerid, -1, &vmr, sizeof(vmr)) == -1)
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
	struct privsep *ps = arg;
	int status, ret = 0;
	uint32_t vmid;
	pid_t pid;
	struct vmop_result vmr;
	struct vmd_vm *vm;

	switch (sig) {
	case SIGCHLD:
		do {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				continue;

			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				vm = NULL;
				if (vm == NULL) {
					/*
					 * If the VM is gone already, it
					 * got terminated via a
					 * IMSG_VMDOP_TERMINATE_VM_REQUEST.
					 */
					continue;
				}

				if (WIFEXITED(status))
					ret = WEXITSTATUS(status);

				/* don't reboot on pending shutdown */
				if (ret == EAGAIN)
					ret = 0;

				vmid = 1;
				if (0) {
					memset(&vmr, 0, sizeof(vmr));
					vmr.vmr_result = ret;
					vmr.vmr_id = vmid;
					if (proc_compose_imsg(ps, PROC_PARENT,
					    -1, IMSG_VMDOP_TERMINATE_VM_EVENT,
					    0, -1, &vmr, sizeof(vmr)) == -1)
						log_warnx("could not signal "
						    "termination of VM %u to "
						    "parent", vmid);
				} else
					log_warnx("could not terminate VM %u",
					    vmid);
			} else
				fatalx("unexpected cause of SIGCHLD");
		} while (pid > 0 || (pid == -1 && errno == EINTR));
		break;
	default:
		fatalx("unexpected signal");
	}
}

/*
 * engine_shutdown
 *
 * Terminate VMs on shutdown to avoid "zombie VM" processes.
 */
void
engine_shutdown(void)
{
}

int
engine_pipe(struct vmd_vm *vm, int fd, void (*cb)(int, short, void *))
{
	struct imsgev	*iev = &vm->vm_iev;

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		log_warn("failed to set nonblocking mode on vm pipe");
		return (-1);
	}

	imsg_init(&iev->ibuf, fd);
	iev->handler = cb;
	iev->data = vm;
	imsg_event_add(iev);

	return (0);
}
