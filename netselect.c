/*
 * Netselect:
 *      Copyright (c) 1998-2001 by Avery Pennarun <apenwarr@worldvisions.ca>
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
 * 3. Neither the name of the University nor the names of its contributors
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
 * I expect this to only compile on Linux.  If it also works on your system,
 * hey, great!  Let me know. -- apenwarr
 */

#ifdef __EMX__
# include <io.h>
# include <fcntl.h>
# include <sys/types.h>
# include <sys/select.h>
# include <machine/endian.h>
#else
# include <endian.h>
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
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
#include <time.h>

#define MAXPACKET	IP_MAXPACKET	/* max ip packet size */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

/*
 * format of a (udp) probe packet.
 */
typedef struct
{
    struct ip ip;
    struct udphdr udp;
    u_char seq;			/* sequence number of this packet */
    u_char ttl;			/* ttl packet left with */
    struct timeval tv;		/* time packet left */
} OPacket;


/* 
 * currently-known information about a host
 */
typedef struct
{
    char *hostname;		/* hostname as provided on command line */
    char *shortname;		/* hostname with any URL-type stuff removed */
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
} HostData;


/* prototypes for functions in this file */
static HostData *add_host(HostData *host, int *numhosts,
			  char *hostname, struct sockaddr_in *addr,
			  int max_ttl);
static char *un_url(char *orig);
static char *fix_url(char *orig, char *hostname);
static HostData *name_resolver(int *numhosts, int numnames, char **names,
			       int max_ttl);

static void send_probe(int seq, int ttl, OPacket *op,
		       HostData *host);
static time_t deltaT(struct timeval *t1p, struct timeval *t2p);
static HostData *wait_for_reply(HostData *hosts, int numhosts,
				       int sock, int msec_timeout);
static HostData *packet_ok(HostData *hosts, int numhosts,
				  u_char *buf, int cc,
				  struct sockaddr_in *from);
static int choose_ttl(HostData *host);
static void usage();
static void results(HostData *hosts, int numhosts, int num_score);
static int host_score(HostData *host);

#define INPACKET_SIZE    512


/* global variables */
static int rcvsock;		/* receive (icmp) socket file descriptor */
static int sndsock;		/* send (udp) socket file descriptor */

static int verbose = 0;
static u_short ident;
static u_short port = 32768 + 666; /* start udp dest port for probe packets */

static int validhosts;

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    int hostcount, startcount, endcount = 0, sent_one, lag, min_lag = 100;
    int ch, seq, ttl, max_ttl = 30, min_tries = 10, num_score = 1;
    struct timeval now;
    struct timezone tz;
    OPacket outpacket;          /* last output (udp) packet */
    HostData *host, *hosts;
    int numhosts, delay, must_continue, count;

    if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0
     || (sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0)
    {
	perror("netselect: socket");
	return 5;
    }

    /* drop root privileges as soon as possible! */
    setuid(getuid());

    seq = 0;

#ifdef __EMX__
    _response(&argc,&argv);
#endif
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
    
    memset(&outpacket, 0, sizeof(OPacket));
    outpacket.ip.ip_tos = 0;
    outpacket.ip.ip_v = IPVERSION;
    outpacket.ip.ip_id = 0;

    ident = (getpid() & 0xffff) | 0x8000;
    
    validhosts = numhosts = 0;
    
    hosts = name_resolver(&numhosts, argc, argv, max_ttl);
    validhosts = numhosts;
    
    if (verbose >= 1)
	fprintf(stderr, "Running netselect to choose %d out of %d address%s.\n",
		num_score, numhosts, numhosts==1 ? "" : "es");
    
    /* keep going until most of the hosts have been finished */
    must_continue = numhosts;
    while (must_continue && must_continue >= numhosts/2)
    {
	gettimeofday(&now, &tz);
	
	must_continue = 0;

	/* send out a packet; if there are no interesting packets to send
	 * out, make sure we only loop once through the list of hosts.
	 * Also make sure that next time we start the loop, we pick up
	 * at the host where we left off, rather than starting over; this
	 * increases fairness.
	 */
	startcount = hostcount = endcount;
	sent_one = 0;
	do
	{
	    hostcount = (hostcount + 1) % numhosts;
	    host = &hosts[hostcount];
	    
	    if (!host->invalid && !host->done
		&& (host->num_out < min_tries
		    || deltaT(&host->send_time, &now) < 5000))
	    {
		must_continue++;
	    }
	    else if (!host->done)
	    {
		host->done = 1;
		validhosts--;
	    }

	    if (host->invalid
	      || (host->retries && deltaT(&host->send_time, &now) < 3000))
		continue;
	    
	    if (host->retries < 3  &&  host->num_out < min_tries)
	    {
		if (!sent_one)
		{
		    if (verbose >= 3 && host->retries >= 1)
			fprintf(stderr, "%-55s - TIMEOUT\n", host->shortname);
		    
		    host->send_time = now;
		    ttl = choose_ttl(host);
		    
		    host->seq = ++seq;
		    seq %= 256;
		    host->retries++;
		    
		    host->num_out++;
		    send_probe(host->seq, ttl, &outpacket, host);
		    endcount = hostcount;
		    sent_one = 1;
		}
	    }
	    else if (host->hops_less_than - host->hops_more_than > 2)
	    {
		/* sometimes we get a TIMEOUT instead of an error if
		 * the ttl is too small; just move to the next one then. */
		host->hops_more_than = choose_ttl(host);
		host->retries = 0;
	    }
	    else
	    {
		if (!host->done)
		    validhosts--;
		host->done = 1;
	    }
	} while (hostcount != startcount);
	
	delay = min_lag/2; /* transmit time must be <= min_lag / 2 */
	if ((host = wait_for_reply(hosts, numhosts, rcvsock, delay)) != NULL)
	{
	    gettimeofday(&now, &tz);
	    delay = 0;

	    if (verbose >= 3)
		fprintf(stderr, "%-35s  %5u ms  %3d hops - ", host->shortname,
		       (unsigned)deltaT(&host->send_time, &now),
		       choose_ttl(host));
	    
	    switch (host->code - 1)
	    {
	    case -2:
		if (verbose >= 3)
		    fprintf(stderr, "HIGHER");
		else if (verbose >= 1)
		    fprintf(stderr, ".");
		if (choose_ttl(host) >= host->hops_less_than)
		    host->hops_less_than = choose_ttl(host) + 1;
		host->hops_more_than = choose_ttl(host);
		host->retries = 0;
		host->num_out--;
		break;
		
	    case ICMP_UNREACH_PORT:
		if (verbose >= 3)
		    fprintf(stderr, "OK");
		else if (verbose >= 1)
		    fprintf(stderr, ".");
		host->hops_less_than = choose_ttl(host);
		host->retries = 0;
		host->num_in++;
		lag = deltaT(&host->send_time, &now);
		if (lag > 10 && lag < min_lag)
		{
		    min_lag = lag;
		    if (verbose >= 3)
			fprintf(stderr, "\nmin_lag is now %d", min_lag);
		}
		host->total_lag += lag;
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
		    fprintf(stderr, "unreachable!\n");
		if (!host->invalid)
		    validhosts--;
		host->invalid = 1;
		break;
	    }

	    if (verbose >= 3)
		fprintf(stderr, "\n");
	}
	    
    }
    
    if (verbose >= 1)
	fprintf(stderr, "\n");
    
    results(hosts, numhosts, num_score);
    
    if (hosts)
    {
	for (count = 0; count < numhosts; count++)
	{
	    free(hosts[count].hostname);
	    free(hosts[count].shortname);
	}
	free(hosts);
    }
    
    return 0;
}


/* 
 * when the newly-created objects are freed, we try to free(hostname)...
 * so make sure it's already dynamically allocated when you call this
 * function!
 */
static HostData *add_host(HostData *hosts, int *numhosts,
			  char *hostname, struct sockaddr_in *addr,
			  int max_ttl)
{
    HostData *host;
    
    (*numhosts)++;
    
    if (!hosts)
	hosts = (HostData *)malloc(sizeof(HostData) * *numhosts);
    else
	hosts = (HostData *)realloc(hosts, sizeof(HostData) * *numhosts);
    
    host = &hosts[*numhosts - 1];
    
    memset(host, 0, sizeof(HostData));
    host->hostname = hostname;
    host->shortname = un_url(hostname);
    if (addr)
	memcpy(&host->addr, addr, sizeof(*addr));
    else
	host->invalid = 1;
    host->hops_less_than = max_ttl;
    
    return hosts;
}


static char *un_url(char *orig)
{
    char *sptr, *eptr, *newbuf;
    
    if ((sptr = strstr(orig, "://")) != NULL)
    {
	/* URL formatted, like: http://hostname:port/dir/file */
	sptr += 3; /* skip :// */
	eptr = strchr(sptr, ':');
	if (!eptr) eptr = strchr(sptr, '/');
	if (!eptr) eptr = strchr(sptr, 0);
	
	newbuf = (char *)malloc(eptr-sptr+1);
	strncpy(newbuf, sptr, eptr-sptr);
	newbuf[eptr-sptr] = 0;
	return newbuf;
    }
    else if ((sptr = strchr(orig, ':')) != NULL)
    {
	/* FTP formatted, like: ftp.debian.org:/debian/foo */
	newbuf = (char *)malloc(sptr-orig+1);
	strncpy(newbuf, orig, sptr-orig);
	newbuf[sptr-orig] = 0;
	return newbuf;
    }
    else /* just plain */
	return strdup(orig);
}


static char *fix_url(char *orig, char *hostname)
{
    char *sptr, *eptr, *newbuf;
    
    if ((sptr = strstr(orig, "://")) != NULL)
    {
	/* URL formatted, like: http://hostname:port/dir/file */
	sptr += 3; /* skip :// */
	eptr = strchr(sptr, ':');
	if (!eptr) eptr = strchr(sptr, '/');
	if (!eptr) eptr = strchr(sptr, 0);
	
	newbuf = (char *)malloc(strlen(orig) + strlen(hostname) + 1);
	strncpy(newbuf, orig, sptr-orig);
	strcpy(newbuf+(sptr-orig), hostname);
	strcat(newbuf, eptr);
	return newbuf;
    }
    else if ((sptr = strchr(orig, ':')) != NULL)
    {
	/* FTP formatted, like: ftp.debian.org:/debian/foo */
	newbuf = (char *)malloc(strlen(orig) + strlen(hostname) + 1);
	strcpy(newbuf, hostname);
	strcat(newbuf, sptr);
	return newbuf;
    }
    else /* just plain */
	return strdup(hostname);
}


/*
 * Resolve all hostnames to IP addresses.  returns the number of hosts that
 * do not have name resolution errors.
 */
static HostData *name_resolver(int *numhosts, int numnames, char **names,
			       int max_ttl)
{
    struct {
	char *hostname;
	int broken, multi;
	struct sockaddr_in addr;
    } result;
    
    HostData *hosts = NULL;
    int closed = 0, active = 0, count = 0, max_active = 24;
    int pipes[2];
    time_t start = time(NULL);
    fd_set rfd, wfd, efd;
    struct timeval tv;
    struct hostent *hp;
    pid_t pid;
    
    if (pipe(pipes))
    {
	perror("netselect pipe");
	validhosts = 0;
    }
    
#ifdef __EMX__
    /* OS/2 uses ASCII mode by default for pipes... */
    setmode(pipes[0],O_BINARY);
    setmode(pipes[1],O_BINARY);
#endif
    
    while (time(NULL) < start + 20)
    {
	if (verbose >= 1)
	{
	    fprintf(stderr, "       \rnetselect: %d (%d active) "
		            "nameserver request(s)...",
		    numnames - count + active, active);
	}

	/* launch new name lookups if we aren't already doing too many */
	while (active < max_active && count < numnames)
	{
	    pid = fork();
	    
	    if (pid == 0) /* child process */
	    {
		alarm(20);
		
		result.hostname = names[count];
		result.multi = result.broken = 0;
		
		/* child task -- actually do name lookup */
		result.addr.sin_family = AF_INET;
		result.addr.sin_addr.s_addr = inet_addr(names[count]);
		
		if (result.addr.sin_addr.s_addr != -1)
		{
		    write(pipes[1], &result, sizeof(result));
		}
		else
		{
		    /* must actually do the name lookup */
		    char *simplename = un_url(result.hostname);
		    hp = gethostbyname(simplename);
		    free(simplename);
		    
		    if (hp)
		    {
			if (hp->h_addrtype != AF_INET 
			    || hp->h_length != sizeof(struct in_addr))
			{
			    result.broken = 1;
			    write(pipes[1], &result, sizeof(result));
			}
			else
			{
			    char **ptr = hp->h_addr_list;
			    
			    result.broken = 0;
			    if (ptr[1])
				result.multi = 1;
			    result.addr.sin_family = AF_INET;
			    
			    while (*ptr)
			    {
				memcpy(&result.addr.sin_addr,
				       *ptr, hp->h_length);
				write(pipes[1], &result, sizeof(result));
				ptr++;
			    }
			}
		    }
		    else
		    {
			result.broken = 1;
			write(pipes[1], &result, sizeof(result));
		    }
		}
		
		_exit(result.broken ? 1 : 0);
	    }
	    else if (pid < 0)
	    {
		/* trouble forking */
		max_active = active-1;
		if (max_active < 1)
		    max_active = 1;
		break;
	    }
	    else
	    {
		/* successful launch */
		active++;
		count++;
		start = time(NULL);
	    }
	} /* end of launcher section */
	
	/* the parent closes the "write" side of the pipe as soon as it
	 * doesn't need any more children; then we know all the children
	 * are dead if selecting on the "read" pipe returns an error.
	 */
	if (!closed && !active)
	{
	    close(pipes[1]);
	    closed = 1;
	}
	
	/* read results from our subtasks */
	tv.tv_sec = active ? 1 : 0;
	tv.tv_usec = 0;
	
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);
	FD_ZERO(&efd);
	FD_SET(pipes[0], &rfd);
	
	if (select(pipes[0] + 1, &rfd, &wfd, &efd, &tv) > 0)
	{
	    if (read(pipes[0], &result, sizeof(result)) != sizeof(result))
	    {
		if (closed && errno == ECHILD)
		    break; /* done resolving */
		else
		    perror("netselect readpipe");
	    }
	    else
	    {
		/* got some kind of result back! */
		if (result.broken)
		{
		    /* name lookup failed */
		    char *simplename = un_url(result.hostname);
		    
		    hosts = add_host(hosts, numhosts, strdup(result.hostname),
				     NULL, max_ttl);
		    if (verbose >= 1)
			fprintf(stderr, "\r%60s\r", "");
		    fprintf(stderr, "netselect: unknown host %s\n", simplename);
		    validhosts--;
		    
		    free(simplename);
		}
		else
		{
		    /* name lookup successful */
		    char *newhostname;
		    
		    if (result.multi)
			newhostname = fix_url(result.hostname,
					      inet_ntoa(result.addr.sin_addr));
		    else
			newhostname = strdup(result.hostname);
		    
		    hosts = add_host(hosts, numhosts, newhostname,
				     &result.addr, max_ttl);
		}
	    }
	}
	
	/* reap dead tasks */
	while (waitpid(-1, NULL, WNOHANG) > 0)
	    active--;
    }
    
    if (verbose >= 1)
    {
	fprintf(stderr, 
		"\r                            "
		"                            \r");
    }
    
    /* reap any remaining tasks */
    while (waitpid(-1, NULL, WNOHANG) > 0)
	active--;
    
    close(pipes[0]);
    close(pipes[1]);
    
    return hosts;
}


static void send_probe(int seq, int ttl, OPacket *op, HostData *host)
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
    ip->ip_len = 0; /* kernel fills this in */
    ip->ip_ttl = ttl;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(ident + seq);

    up->uh_sport = htons(ident);
    up->uh_dport = htons(port + seq);
    up->uh_ulen = htons((u_short)(sizeof(OPacket) - sizeof(struct ip)));
    up->uh_sum = 0;
    
    if (verbose >= 4)
    	fprintf(stderr, "%-35s>>\n", host->shortname);

    i = sendto(sndsock, op, sizeof(OPacket), 0,
	       (struct sockaddr *)&host->addr, sizeof(host->addr));
    if (i < 0 || i != sizeof(OPacket))
    {
	if (i < 0)
	{
	    switch (errno)
	    {
	    case ENETDOWN:
	    case ENETUNREACH:
	    case EHOSTDOWN:
	    case EHOSTUNREACH:
		if (verbose >= 3)
		    fprintf(stderr, "unreachable or down!\n");
		if (!host->invalid)
		    validhosts--;
		host->invalid = 1;
		break;
		
	    default:
		perror("sendto");
	    }
	}
	fflush(stdout);
    }
}


static time_t deltaT(struct timeval *t1p, struct timeval *t2p)
{
    return (t2p->tv_sec - t1p->tv_sec) * 1000
	 + (t2p->tv_usec - t1p->tv_usec) / 1000;
}


static HostData *wait_for_reply(HostData *hosts, int numhosts,
				       int sock, int msec_timeout)
{
    fd_set fds;
    struct timeval wait, start_time;
    struct timezone tz;
    u_char inpacket[INPACKET_SIZE];
    struct sockaddr_in from;
    int cc = 0;
    time_t msec_used;
    HostData *host;
    
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


static HostData *packet_ok(HostData *hosts, int numhosts,
				  u_char * buf, int cc,
				  struct sockaddr_in *from)
{
    u_char type, code;
    int hlen;
    struct ip *ip;
    struct icmp *icp;
    HostData *host;
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

    /* fprintf(stderr, "received an unknown packet!\n"); */
    return NULL;
}


static int choose_ttl(HostData *host)
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


static void results(HostData *hosts, int numhosts, int num_score)
{
    int count, lowest_score, score;
    HostData *host, *lowest_host;
    
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
	
	if (num_score > 0)
	    num_score--;
    }
}


static int host_score(HostData *host)
{
    int score;
    
    if (!host->num_in || host->invalid)
	return 99999; /* rotten score */

    score = host->total_lag * host->num_out / host->num_in / host->num_in;
    score = score + (score * host->hops_less_than / 10);
    
    return score;
}
