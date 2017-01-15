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

void vmm_sighdlr(int, short, void *);
int opentap(char *);
int start_vm(struct imsg *, uint32_t *);
int get_info_vm(struct privsep *, struct imsg *, int);
int vmm_dispatch_parent(int, struct privsep_proc *, struct imsg *);
void vmm_run(struct privsep *, struct privsep_proc *, void *);
int vcpu_pic_intr(uint32_t, uint32_t, uint8_t);

int vmm_pipe(struct vmd_vm *, int, void (*)(int, short, void *));
void vmm_dispatch_vm(int, short, void *);
void vm_dispatch_vmm(int, short, void *);

int con_fd;
struct vmd_vm *current_vm;

extern struct vmd *env;

extern char *__progname;

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	vmm_dispatch_parent  },
};

void
vmm(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), vmm_run, NULL);
}

void
vmm_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	if (config_init(ps->ps_env) == -1)
		fatal("failed to initialize configuration");

	signal_del(&ps->ps_evsigchld);
	signal_set(&ps->ps_evsigchld, SIGCHLD, vmm_sighdlr, ps);
	signal_add(&ps->ps_evsigchld, NULL);

	/*
	 * pledge in the vmm process:
 	 * stdio - for malloc and basic I/O including events.
	 * vmm - for the vmm ioctls and operations.
	 * proc - for forking and maitaining vms.
	 * recvfd - for disks, interfaces and other fds.
	 */
	if (pledge("stdio vmm recvfd proc", NULL) == -1)
		fatal("pledge");

	/* Get and terminate all running VMs */
	get_info_vm(ps, NULL, 1);
}

int
vmm_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
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
	case IMSG_VMDOP_START_VM_DISK:
		res = config_getdisk(ps, imsg);
		if (res == -1) {
			res = errno;
			cmd = IMSG_VMDOP_START_VM_RESPONSE;
		}
		break;
	case IMSG_VMDOP_START_VM_IF:
		res = config_getif(ps, imsg);
		if (res == -1) {
			res = errno;
			cmd = IMSG_VMDOP_START_VM_RESPONSE;
		}
		break;
	case IMSG_VMDOP_START_VM_END:
		res = start_vm(imsg, &id);
		cmd = IMSG_VMDOP_START_VM_RESPONSE;
		break;
	case IMSG_VMDOP_TERMINATE_VM_REQUEST:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));
		id = 1;

		if ((vm = vm_getbyid(id)) != NULL &&
		    vm->vm_shutdown == 0) {
			log_debug("%s: sending shutdown request to vm %d",
			    __func__, id);

			/*
			 * Request reboot but mark the VM as shutting down.
			 * This way we can terminate the VM after the triple
			 * fault instead of reboot and avoid being stuck in
			 * the ACPI-less powerdown ("press any key to reboot")
			 * of the VM.
			 */
			vm->vm_shutdown = 1;
			if (imsg_compose_event(&vm->vm_iev,
			    IMSG_VMDOP_VM_REBOOT, 0, 0, -1, NULL, 0) == -1)
				res = errno;
			else
				res = 0;
		} else {
			/* Terminate VMs that are unknown or shutting down */
			res = 0;
			vm_remove(vm);
		}
		cmd = IMSG_VMDOP_TERMINATE_VM_RESPONSE;
		break;
	case IMSG_VMDOP_GET_INFO_VM_REQUEST:
		res = get_info_vm(ps, imsg, 0);
		cmd = IMSG_VMDOP_GET_INFO_VM_END_DATA;
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));

		if (mode & CONFIG_VMS) {
			/* Terminate and remove all VMs */
			vmm_shutdown();
			mode &= ~CONFIG_VMS;
		}

		config_getreset(env, imsg);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);

		/* Forward message to each VM process */
		TAILQ_FOREACH(vm, env->vmd_vms, vm_entry) {
			imsg_compose_event(&vm->vm_iev,
			    imsg->hdr.type, imsg->hdr.peerid, imsg->hdr.pid,
			    -1, &verbose, sizeof(verbose));
		}
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	case IMSG_VMDOP_START_VM_RESPONSE:
		if (res != 0) {
			/* Remove local reference if it exists */
			if ((vm = vm_getbyvmid(imsg->hdr.peerid)) != NULL)
				vm_remove(vm);
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
vmm_sighdlr(int sig, short event, void *arg)
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
				vm = vm_getbypid(pid);
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
				if (ret == EAGAIN && vm->vm_shutdown)
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

				vm_remove(vm);
			} else
				fatalx("unexpected cause of SIGCHLD");
		} while (pid > 0 || (pid == -1 && errno == EINTR));
		break;
	default:
		fatalx("unexpected signal");
	}
}

/*
 * vmm_shutdown
 * 
 * Terminate VMs on shutdown to avoid "zombie VM" processes.
 */
void
vmm_shutdown(void)
{
	struct vmd_vm *vm, *vm_next;

	TAILQ_FOREACH_SAFE(vm, env->vmd_vms, vm_entry, vm_next) {
		vm_remove(vm);
	}
}

int
vmm_pipe(struct vmd_vm *vm, int fd, void (*cb)(int, short, void *))
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

void
vmm_dispatch_vm(int fd, short event, void *arg)
{
	struct vmd_vm		*vm = arg;
	struct imsgev		*iev = &vm->vm_iev;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	ssize_t			 n;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("%s: imsg_read", __func__);
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			return;
		}
	}

	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("%s: msgbuf_write fd %d", __func__, ibuf->fd);
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			event_del(&iev->ev);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)
			break;

#if DEBUG > 1
		log_debug("%s: got imsg %d from %s",
		    __func__, imsg.hdr.type,
		    vm->vm_params.vmc_params.vcp_name);
#endif

		switch (imsg.hdr.type) {
		default:
			fatalx("%s: got invalid imsg %d", __func__,
			    imsg.hdr.type);
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
vm_dispatch_vmm(int fd, short event, void *arg)
{
	struct vmd_vm		*vm = arg;
	struct imsgev		*iev = &vm->vm_iev;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 verbose;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("%s: imsg_read", __func__);
		if (n == 0)
			_exit(0);
	}

	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("%s: msgbuf_write fd %d", __func__, ibuf->fd);
		if (n == 0)
			_exit(0);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)
			break;

#if DEBUG > 1
		log_debug("%s: got imsg %d from %s",
		    __func__, imsg.hdr.type,
		    vm->vm_params.vmc_params.vcp_name);
#endif

		switch (imsg.hdr.type) {
		case IMSG_CTL_VERBOSE:
			IMSG_SIZE_CHECK(&imsg, &verbose);
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			break;
		case IMSG_VMDOP_VM_SHUTDOWN:
			break;
		case IMSG_VMDOP_VM_REBOOT:
			break;
		default:
			fatalx("%s: got invalid imsg %d",
			    __func__, imsg.hdr.type);
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

int
get_info_vm(struct privsep *ps, struct imsg *imsg, int terminate)
{
	size_t i;
	char vir[22];

	/* Return info */
	for (i = 0; i < 1; i++) {
		if (proc_compose_imsg(ps, PROC_PARENT, -1,
		    IMSG_VMDOP_GET_INFO_VM_DATA, imsg->hdr.peerid, -1,
		    &vir, sizeof(vir)) == -1)
			return (EIO);
	}
	return (0);
}

/*
 * fd_hasdata
 *
 * Determines if data can be read from a file descriptor.
 *
 * Parameters:
 *  fd: the fd to check
 *
 * Return values:
 *  1 if data can be read from an fd, or 0 otherwise.
 */
int
fd_hasdata(int fd)
{
	struct pollfd pfd[1];
	int nready, hasdata = 0;

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	nready = poll(pfd, 1, 0);
	if (nready == -1)
		log_warn("checking file descriptor for data failed");
	else if (nready == 1 && pfd[0].revents & POLLIN)
		hasdata = 1;
	return (hasdata);
}
