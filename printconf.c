/*	$OpenBSD$	*/

/*
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
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
#include <sys/socket.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>

#include "proc.h"
#include "newd.h"

void print_config(struct newd *);

void
print_config(struct newd *conf)
{
	struct group *g;
	char buf[INET6_ADDRSTRLEN], *bufp;

	printf("yesno %s\n", conf->newd_yesno ? "yes" : "no");
	printf("integer %d\n", conf->newd_integer);
	printf("\n");

	printf("global_text \"%s\"\n", conf->newd_global_text);
	printf("\n");


	LIST_FOREACH(g, conf->newd_groups, entry) {
		printf("group %s {\n", g->newd_group_name);

		printf("\tyesno %s\n", g->newd_group_yesno ? "yes" : "no");
		printf("\tinteger %d\n", g->newd_group_integer);

		bufp = inet_net_ntop(AF_INET, &g->newd_group_v4address,
		    g->newd_group_v4_bits, buf, sizeof(buf));
		printf("\tgroup-v4address %s\n",
		    bufp ? bufp : "<invalid IPv4>");
		bufp = inet_net_ntop(AF_INET6, &g->newd_group_v6address,
		    g->newd_group_v6_bits, buf, sizeof(buf));
		printf("\tgroup-v6address %s\n",
		    bufp ? bufp : "<invalid IPv6>");

		printf("}\n");
	}
}
