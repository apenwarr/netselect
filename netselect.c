/*
 * Netselect:
 *      Copyright (c) 1998 by Avery Pennarun <apenwarr@worldvisions.ca>
 *
 * Traceroute:
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 * 
 * This code is derived from software contributed to Berkeley by
 * Van Jacobson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Expect this to only compile on Linux.  If it works on your system, hey,
 * great!  Let me know. -- apenwarr
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <endian.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define	MAXPACKET	65535	/* max ip packet size */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

/*
 * format of a (udp) probe packet.
 */
struct opacket
{
    struct ip ip;
    struct udphdr udp;
    u_char seq;			/* sequence number of this packet */
    u_char ttl;			/* ttl packet left with */
    struct timeval tv;		/* time packet left */
};


/* 
 * currently-known information about a host
 */
struct hostdata
{
    char *hostname;		/* hostname as provided on command line */

    pid_t resolver_pid; 	/* >0 if DNS lookup in progress */
    int resolver_done;		/* !=0 if resolver finished */
    struct sockaddr_in addr;	/* remote address */

    int invalid;		/* !=0 if we discard this host */
    int done;			/* !=0 if host testing is done */

    unsigned num_out, num_in;	/* packets sent/received successfully */
    unsigned total_lag;		/* combined lag on ALL received messages */
    int hops_less_than, hops_more_than; /* for guessing number of hops */
    
    int retries;		/* transaction in progress */
    struct timeval send_time;	/* time of transmission */
    int code;			/* ICMP error code returned */
    u_short seq;		/* sequence number sent with packet */
};


/* prototypes for functions in this file */
static void set_up_host(struct hostdata *host, char *hostname, int max_ttl);
static int name_resolver(struct hostdata *hosts, int numhosts);

static void send_probe(int seq, int ttl, struct opacket *op,
		       struct hostdata *host);
static time_t deltaT(struct timeval *t1p, struct timeval *t2p);
static struct hostdata *wait_for_reply(struct hostdata *hosts, int numhosts,
				       int sock, int msec_timeout);
static struct hostdata *packet_ok(struct hostdata *hosts, int numhosts,
				  u_char *buf, int cc,
				  struct sockaddr_in *from);
static int choose_ttl(struct hostdata *host);
static void usage();
static void results(struct hostdata *hosts, int numhosts, int num_score);
static int host_score(struct hostdata *host);

#define INPACKET_SIZE    512


/* global variables */
static int rcvsock;		/* receive (icmp) socket file descriptor */
static int sndsock;		/* send (udp) socket file descriptor */

static int verbose = 0;
static u_short ident;
static u_short port = 32768 + 666; /* start udp dest port for probe packets */

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    int hostcount, ch, seq, ttl, max_ttl = 30, min_tries = 10, num_score = 1;
    struct timeval now;
    struct timezone tz;
    struct opacket outpacket;          /* last output (udp) packet */
    struct hostdata *host, *hosts;
    int numhosts, validhosts, delay, must_continue;

    if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0
     || (sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0)
    {
	perror("netselect: socket");
	return 5;
    }

    /* drop root privileges as soon as possible! */
    setuid(getuid());

    seq = 0;

    while ((ch = getopt(argc, argv, "s:t:m:v?")) != EOF)
    {
	switch (ch)
	{
	case 's':
	    num_score = atoi(optarg);
	    break;
	    
	case 't':
	    min_tries = atoi(optarg);
	    if (min_tries < 1)
	    {
		fprintf(stderr, "netselect: number of tries must be >1.\n");
		return 1;
	    }
	    break;
	    
	case 'm':
	    max_ttl = atoi(optarg);
	    if (max_ttl <= 1)
	    {
		fprintf(stderr, "netselect: max ttl must be >1.\n");
		return 1;
	    }
	    break;

	case 'v':
	    verbose++;
	    break;
	    
	case '?':
	default:
	    usage();
	    return 1;
	}
    }

    argc -= optind;
    argv += optind;

    if (argc < 1)
    {
	usage();
	return 1;
    }
    
    memset(&outpacket, 0, sizeof(struct opacket));
    outpacket.ip.ip_tos = 0;
    outpacket.ip.ip_v = IPVERSION;
    outpacket.ip.ip_id = 0;

    ident = (getpid() & 0xffff) | 0x8000;
    hosts = (struct hostdata *)calloc(argc, sizeof(struct hostdata));
    
    validhosts = 0;
    
    for (numhosts = 0; numhosts < argc; numhosts++)
	set_up_host(hosts + numhosts, argv[numhosts], max_ttl);
    
    validhosts = name_resolver(hosts, numhosts);
    
    must_continue = numhosts;
    while (must_continue && must_continue >= numhosts/2)
    {
	gettimeofday(&now, &tz);
	
	must_continue = 0;
	
	for (hostcount = 0, host = hosts;
	     hostcount < numhosts;  hostcount++, host++)
	{
	    if (!host->invalid && !host->done
		&& (host->num_out < min_tries
		    || deltaT(&host->send_time, &now) < 5000))
	    {
		must_continue++;
	    }
	    else
	    {
		host->done = 1;
		validhosts--;
	    }

	    if (host->invalid || hostcount > (numhosts - validhosts + 5)
		|| (host->retries && deltaT(&host->send_time, &now) < 5000))
		continue;
	    
	    host->send_time = now;
	    ttl = choose_ttl(host);
	    
	    gettimeofday(&host->send_time, &tz);
	    host->seq = ++seq;
	    seq %= 256;
	    host->retries++;
	    
	    if (host->retries < 3  &&  host->num_out < min_tries)
	    {
		if (verbose >= 3 && host->retries > 1)
		    fprintf(stderr, "%-55s - TIMEOUT\n", host->hostname);
		
		host->num_out++;
		send_probe(host->seq, ttl, &outpacket, host);
	    }
	    else if (host->hops_less_than - host->hops_more_than > 2)
	    {
		host->hops_more_than = choose_ttl(host);
		host->retries = 0;
	    }
	    else
	    {
		if (!host->done)
		    validhosts--;
		host->done = 1;
	    }
	}
	
	delay = 100;
	while ((host = wait_for_reply(hosts, numhosts, rcvsock, delay))
	          != NULL)
	{
	    gettimeofday(&now, &tz);
	    delay = 0;

	    if (verbose >= 3)
		fprintf(stderr, "%-35s  %5u ms  %3d hops - ", host->hostname,
		       (unsigned)deltaT(&host->send_time, &now),
		       choose_ttl(host));
	    
	    switch (host->code - 1)
	    {
	    case -2:
		if (verbose >= 3)
		    fprintf(stderr, "HIGHER");
		if (choose_ttl(host) >= host->hops_less_than)
		    host->hops_less_than = choose_ttl(host) + 1;
		host->hops_more_than = choose_ttl(host);
		host->retries = 0;
		host->num_out--;
		break;
		
	    case ICMP_UNREACH_PORT:
		if (verbose >= 3)
		    fprintf(stderr, "OK");
		host->hops_less_than = choose_ttl(host);
		host->retries = 0;
		host->num_in++;
		host->total_lag += deltaT(&host->send_time, &now);
		break;
		
	    case ICMP_UNREACH_NET:
	    case ICMP_UNREACH_HOST:
	    case ICMP_UNREACH_PROTOCOL:
	    case ICMP_UNREACH_NEEDFRAG:
	    case ICMP_UNREACH_SRCFAIL:
	    case ICMP_UNREACH_FILTER_PROHIB:
	    case ICMP_UNREACH_NET_PROHIB:	/* misuse */
	    case ICMP_UNREACH_HOST_PROHIB:
	    case ICMP_UNREACH_NET_UNKNOWN:
	    case ICMP_UNREACH_HOST_UNKNOWN:
	    case ICMP_UNREACH_ISOLATED:
	    case ICMP_UNREACH_TOSNET:
	    case ICMP_UNREACH_TOSHOST:
		if (verbose >= 3)
		    fprintf(stderr, "unreachable!");
		if (!host->invalid)
		    validhosts--;
		host->invalid = 1;
		break;
	    }

	    if (verbose >= 3)
		fprintf(stderr, "\n");
	}
	    
    }
    
    results(hosts, numhosts, num_score);
    
    return 0;
}


static void set_up_host(struct hostdata *host, char *hostname, int max_ttl)
{
    host->hostname = hostname;
    host->resolver_pid = 0;  /* not resolving yet */
    host->hops_less_than = max_ttl;
    
    memset(&host->addr, 0, sizeof(host->addr));
}


/*
 * Resolve all hostnames to IP addresses.  returns the number of hosts that
 * do not have name resolution errors.
 */
static int name_resolver(struct hostdata *hosts, int numhosts)
{
    struct {
	int which_host;
	int broken;
	struct sockaddr_in addr;
    } result;
    
    struct hostdata *host;
    int validhosts = numhosts, notdone = numhosts, active = 0, toobusy = 0;
    int count;
    int pipes[2];
    time_t start = time(NULL);
    fd_set rfd, wfd, efd;
    struct timeval tv;
    struct hostent *hp;
    
    if (pipe(pipes))
    {
	perror("netselect pipe");
	return 0;
    }
    
    while (notdone > 0  &&  time(NULL) < start + 20)
    {
	if (verbose >= 1)
	{
	    fprintf(stderr, "       \rnetselect: %d (%d active) "
		            "nameserver request(s)...",
		    notdone, active);
	}
	

	/* launch new name lookups if there is room */
	for (host = hosts, count = 0;
	     active < notdone && !toobusy && active < 24 && count < numhosts;
	     count++, host++)
	{
	    if (host->invalid || host->resolver_done || host->resolver_pid)
		continue; /* skip this one */
	    
	    host->resolver_pid = fork();
	    
	    if (host->resolver_pid == 0)
	    {
		result.which_host = count;
		
		/* child task -- actually do name lookup */
		result.addr.sin_family = AF_INET;
		result.addr.sin_addr.s_addr = inet_addr(host->hostname);
		
		if (result.addr.sin_addr.s_addr != -1)
		{
		    result.broken = 0;
		}
		else
		{
		    /* must actually do the name lookup */
		    hp = gethostbyname(host->hostname);
		    if (hp)
		    {
			if (hp->h_addrtype != AF_INET 
			    || hp->h_length != sizeof(struct in_addr))
			    result.broken = 1;
			else
			{
			    result.broken = 0;
			    result.addr.sin_family = AF_INET;
			    memcpy(&result.addr.sin_addr,
				   hp->h_addr, hp->h_length);
			}
		    }
		    else
		    {
			result.broken = 1;
		    }
		}
		
		write(pipes[1], &result, sizeof(result));
		_exit(result.broken ? 1 : 0);
	    }
	    else if (host->resolver_pid < 0)
	    {
		/* trouble forking */
		toobusy = 1;
		break;
	    }
	    else
	    {
		/* successful launch */
		active++;
		start = time(NULL);
	    }
	} /* end of launcher clause */
	
	/* reap dead tasks */
	while (waitpid(-1, NULL, WNOHANG) > 0)
	    toobusy = 0;
	
	/* read results from our subtasks */
	tv.tv_sec = active ? 1 : 0;
	tv.tv_usec = 0;
	
	for (;;)
	{
	    FD_ZERO(&rfd);
	    FD_ZERO(&wfd);
	    FD_ZERO(&efd);
	    FD_SET(pipes[0], &rfd);
	    
	    if (select(pipes[0] + 1, &rfd, &wfd, &efd, &tv) > 0)
	    {
		if (read(pipes[0], &result, sizeof(result)) != sizeof(result))
		{
		    perror("netselect readpipe");
		}
		else
		{
		    /* got some kind of result back! */
		    host = &hosts[result.which_host];
		    host->resolver_pid = 0;
		    host->resolver_done = 1;
		    notdone--;
		    active--;
		    
		    if (result.broken)
		    {
			/* name lookup failed */
			if (verbose >= 1)
			{
			    fprintf(stderr, 
				    "\r                            "
				    "                            \r");
			}
			fprintf(stderr,
				"netselect: unknown host %s\n",
				host->hostname);
			host->invalid = 1;
			validhosts--;
		    }
		    else
		    {
			/* name lookup successful */
			memcpy(&host->addr, &result.addr, sizeof(host->addr));
 			/* printf("%s %s\n", host->hostname,
				inet_ntoa(host->addr.sin_addr)); */
		    }
		}
	    }
	    else
		break;
	    
	    tv.tv_sec = tv.tv_usec = 0; /* keep reading, but no delays! */
	}
    }
    
    if (verbose >= 1)
    {
	fprintf(stderr, 
		"\r                            "
		"                            \r");
    }
    
    validhosts -= notdone;

    /* finally, clean up any timed-out entries */

    for (host = hosts, count = 0; count < numhosts; count++, host++)
    {
	if (host->resolver_pid)
	{
	    kill(host->resolver_pid, SIGKILL);
	    host->resolver_pid = 0;
	    host->resolver_done = 1;
	    host->invalid = 1;
	    
	    fprintf(stderr, "netselect: nameserver timeout %s\n",
		    host->hostname);
	}
    }
    
    /* reap any remaining tasks */
    while (waitpid(-1, NULL, WNOHANG) > 0)
	;
    
    close(pipes[0]);
    close(pipes[1]);
    
    return validhosts;
}


static void send_probe(int seq, int ttl, struct opacket *op,
		       struct hostdata *host)
{
    struct ip *ip = &op->ip;
    struct udphdr *up = &op->udp;
    struct timezone tz;
    int i;

    op->ip.ip_dst = host->addr.sin_addr;
    op->seq = seq;
    op->ttl = ttl;
    gettimeofday(&op->tv, &tz);

    ip->ip_off = 0;
    ip->ip_hl = sizeof(*ip) >> 2;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_len = htons((u_short) sizeof(struct opacket));
    ip->ip_ttl = ttl;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(ident + seq);

    up->uh_sport = htons(ident);
    up->uh_dport = htons(port + seq);
    up->uh_ulen = htons((u_short)(sizeof(struct opacket) - sizeof(struct ip)));
    up->uh_sum = 0;

    i = sendto(sndsock, op, sizeof(struct opacket), 0,
	       (struct sockaddr *)&host->addr, sizeof(host->addr));
    if (i < 0 || i != sizeof(struct opacket))
    {
	if (i < 0)
	    perror("sendto");
	fflush(stdout);
    }
}


static time_t deltaT(struct timeval *t1p, struct timeval *t2p)
{
    return (t2p->tv_sec - t1p->tv_sec) * 1000
	 + (t2p->tv_usec - t1p->tv_usec) / 1000;
}


static struct hostdata *wait_for_reply(struct hostdata *hosts, int numhosts,
				       int sock, int msec_timeout)
{
    fd_set fds;
    struct timeval wait, start_time;
    struct timezone tz;
    u_char inpacket[INPACKET_SIZE];
    struct sockaddr_in from;
    int cc = 0;
    time_t msec_used;
    struct hostdata *host;
    
#if !defined(__GLIBC__)
    int fromlen = sizeof(from);
#else				/* __GLIBC__ */
    size_t fromlen = sizeof(from);
#endif				/* __GLIBC__ */

    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    gettimeofday(&start_time, &tz);

    for (;;)
    {
	gettimeofday(&wait, &tz);
	msec_used = deltaT(&start_time, &wait);
	if (msec_used > msec_timeout)
	    break;	       /* timed out */
	
	wait.tv_usec = (msec_timeout - msec_used) * 1000;
	wait.tv_sec = 0;
	
	if (select(sock + 1, &fds, NULL, NULL, &wait) > 0)
	{
	    cc = recvfrom(rcvsock, inpacket, INPACKET_SIZE, 0,
			  (struct sockaddr *) &from, &fromlen);
	    if (cc > 0)
	    {
		if ((host = packet_ok(hosts, numhosts, inpacket, cc, &from))
		            != NULL)
		    return host;
	    }
	}
    }
    
    return NULL;
}


static struct hostdata *packet_ok(struct hostdata *hosts, int numhosts,
				  u_char * buf, int cc,
				  struct sockaddr_in *from)
{
    u_char type, code;
    int hlen;
    struct ip *ip;
    struct icmp *icp;
    struct hostdata *host;
    int hcount;

    ip = (struct ip *) buf;
    hlen = ip->ip_hl << 2;
    if (cc < hlen + ICMP_MINLEN)
	return 0;
    cc -= hlen;
    icp = (struct icmp *) (buf + hlen);

    type = icp->icmp_type;
    code = icp->icmp_code;
    if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS)
	|| type == ICMP_UNREACH)
    {
	struct ip *hip;
	struct udphdr *up;

	hip = &icp->icmp_ip;
	hlen = hip->ip_hl << 2;
	up = (struct udphdr *) ((u_char *) hip + hlen);
	
	for (hcount = 0, host = hosts; hcount < numhosts; hcount++, host++)
	{
	    if (host->invalid) continue;
	    
	    if (hlen + 12 <= cc && hip->ip_p == IPPROTO_UDP &&
		up->uh_sport == htons(ident) &&
		up->uh_dport == htons(port + host->seq))
	    {
		host->code = (type == ICMP_TIMXCEED ? -1 : code + 1);
		return host;
	    }
	}
    }

    return NULL;
}


static int choose_ttl(struct hostdata *host)
{
    if (!host || host->invalid)
	return 0;

    /* converge upwards to hops_less_than -- manages rounding errors */
    return host->hops_less_than 
	      - (host->hops_less_than - host->hops_more_than)/2;
}


static void usage(void)
{
    fprintf(stderr,
	    "Usage: netselect [-v] [-vv] [-t min_tries] [-m max_ttl]"
	    " host [host...]\n");
}


static void results(struct hostdata *hosts, int numhosts, int num_score)
{
    int count, lowest_score, score;
    struct hostdata *host, *lowest_host;
    
    if (verbose >= 3)
	fprintf(stderr, "\n");
    
    if (verbose >= 2)
    {
	for (count = 0, host = hosts; count < numhosts; count++, host++)
	{
	    if (!host->num_in || !host->num_out)
		printf("%-35s  %5u ms  %2d hops  %3d%% ok\n",
		       host->hostname, 9999, host->hops_less_than, 0);
	    else
		printf("%-35s  %5u ms  %2d hops  %3d%% ok (%2d/%2d) [%5d]\n",
		       host->hostname, host->total_lag / host->num_in,
		       host->hops_less_than,
		       host->num_in * 100 / host->num_out,
		       host->num_in, host->num_out, host_score(host));
	}
    }
    
    while (num_score)
    {
	lowest_score = 99999;
	lowest_host = NULL;
	
	for (host = hosts, count = 0; count < numhosts; count++, host++)
	{
	    if (host->invalid) continue;
	    
	    score = host_score(host);
	    if (score < lowest_score)
	    {
		lowest_score = score;
		lowest_host = host;
	    }
	}
	
	if (!lowest_host)
	    break;
	    
	printf("%5d %s\n", lowest_score, lowest_host->hostname);
	lowest_host->invalid = 1; /* skip this one next time */
	num_score--;
    }
}


static int host_score(struct hostdata *host)
{
    int score;
    
    if (!host->num_in || host->invalid)
	return 99999; /* rotten score */

    score = host->total_lag * host->num_out / host->num_in / host->num_in;
    score = score + (score * host->hops_less_than / 10);
    
    return score;
}
