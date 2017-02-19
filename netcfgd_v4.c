/*	$OpenBSD$	*/

/*
 * Copyright 2017 Kenneth R Westerback <krw@openbsd.org>
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

#include <sys/socket.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>

#include <event.h>
#include <imsg.h>
#include <log.h>

#include "netcfgd.h"

void
v4_execute_proposal(struct imsg *imsg)
{
	/*
	 * Steps from dhclient:
	 * 1) Delete addresses.
	 * 2) Flush routes.
	 * 3) Set MTU.
	 * 4) Add address.
	 * 5) Add static routes (including default route.).
	 * 6) Update resolv.conf.
	 */

	log_warnx("Executing v4 proposal");
}
