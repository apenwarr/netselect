/*
 * Netselect:
 *      Copyright (c) 1998-2010 by Avery Pennarun <apenwarr@gmail.com>
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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
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
 * format of a (icmp) probe packet.
 */
typedef struct
{
    struct ip ip;
    struct icmp icmp;
    u_char seq;			/* sequence number of this packet */
    u_char ttl;			/* ttl packet left with */
    struct timeval tv;		/* time packet left */
}__attribute__((packed)) IPacket;

/*
 * format of a (headerless udp) probe packet.
 */
typedef struct
{
    struct udphdr udp;
    u_char seq;			/* sequence number of this packet */
    u_char ttl;			/* ttl packet left with */
    struct timeval tv;		/* time packet left */
} OPacket6;

/*
 * format of a (icmpv6) probe packet.
 */
typedef struct
{
    struct icmp6_hdr icmp6;	/* icmp6 contains seq (id) and ttl (seq)
                                 * fields already */
    struct timeval tv;		/* time packet left */
}__attribute__((packed)) I6Packet;

/* 
 * currently-known information about a host
 */
typedef struct
{
    char *hostname;		/* hostname as provided on command line */
    char *shortname;		/* hostname with any URL-type stuff removed */
    struct sockaddr_storage addr;	/* remote address */

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
			  char *hostname, struct sockaddr *addr,
			  int max_ttl);
static char *un_url(char *orig);
static char *fix_url(char *orig, struct sockaddr *addr);
static HostData *name_resolver(int *numhosts, int numnames, char **names,
			       int max_ttl);

static void send_probe(int seq, int ttl, OPacket *op,
		       HostData *host);
static void send_probe6(int seq, int ttl, OPacket6 *op,
		       HostData *host);
static void send_icmp_probe(int seq, int ttl, IPacket *op,
		       HostData *host);
static void send_icmp6_probe(int seq, int ttl, I6Packet *op,
		       HostData *host);
static time_t deltaT(struct timeval *t1p, struct timeval *t2p);
static HostData *wait_for_reply(HostData *hosts, int numhosts,
				       int msec_timeout);
static HostData *packet_ok(HostData *hosts, int numhosts,
				  u_char *buf, int cc,
				  struct sockaddr_in *from);
static HostData *packet6_ok(HostData *hosts, int numhosts,
				  u_char *buf, int cc,
				  struct sockaddr_in6 *from);
static int choose_ttl(HostData *host);
static void usage();
static void results(HostData *hosts, int numhosts, int num_score);
static int host_score(HostData *host);

#define INPACKET_SIZE    512


/* global variables */
static int rcvsock;		/* receive (icmp) socket file descriptor */
static int rcvsock6;		/* IPv6 receive (icmp) socket file descriptor */
static int sndsock;		/* send (udp) socket file descriptor */
static int sndsock6;		/* IPv6 send socket file descriptor */

static int verbose = 0;
static u_short ident;
static u_short port = 32768 + 666; /* start udp dest port for probe packets */

static int validhosts;

static int addr_fam = AF_UNSPEC;

int main(int argc, char **argv)
{
    extern char *optarg;
    extern int optind;
    int hostcount, startcount, endcount = 0, sent_one, lag, min_lag = 100;
    int ch, seq, ttl, max_ttl = 30, num_score = 1;
    int use_icmp = 0;
    int sock_v6_only = 1;
    unsigned int min_tries = 10;
    struct timeval now;
    struct timezone tz;
    OPacket udppacket;          /* last output (udp) packet */
    IPacket icmppacket;         /* last output (icmp) packet */
    OPacket6 udppacket6;        /* last output (headerless udp) packet */
    I6Packet icmp6packet;       /* last output (icmp6) packet */
    
    HostData *host, *hosts;
    int numhosts, delay, must_continue, count, port_unreachable, other_unreachable;
    int socket_errno = 0;

    if (geteuid () != 0)
        fprintf (stderr, "%s: root privileges required\n", argv[0]);

    if ((rcvsock  = socket(AF_INET,  SOCK_RAW, IPPROTO_ICMP)) < 0
     || (sndsock  = socket(AF_INET,  SOCK_RAW, IPPROTO_RAW )) < 0
     || (rcvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
	/* Capture errno so that command-line options can be parsed.
	   We delay reporting an error until this has happened. */
	socket_errno = errno;
    }

    /* drop root privileges as soon as possible! */
    setuid(getuid());

    seq = 0;

#ifdef __EMX__
    _response(&argc,&argv);
#endif
    while ((ch = getopt(argc, argv, "s:t:m:Iv?46")) != EOF)
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

	case 'I':
            use_icmp = 1;
	    break;

	case '4':
            addr_fam = AF_INET;
	    break;

	case '6':
            addr_fam = AF_INET6;
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

    /* Was there an error acquiring a socket? */
    if (socket_errno)
    {
	errno = socket_errno;
	perror("netselect: socket");
	return 5;
    }

    if (addr_fam == AF_INET)
    {
	close(rcvsock6);
	rcvsock6 = -1;
    }
    else if (addr_fam == AF_INET6)
    {
	close(rcvsock);
	rcvsock = -1;
    }

    ident = (getpid() & 0xffff) | 0x8000;

    if ( use_icmp )  
    {
        memset(&icmppacket, 0, sizeof(IPacket));
        icmppacket.ip.ip_tos = 0;
        icmppacket.ip.ip_v = IPVERSION;
        icmppacket.ip.ip_id = 0;

        sndsock6 = rcvsock6;
    } 
    else 
    {
        memset(&udppacket, 0, sizeof(OPacket));
        udppacket.ip.ip_tos = 0;
        udppacket.ip.ip_v = IPVERSION;
        udppacket.ip.ip_id = 0;

	if (addr_fam != AF_INET)
	{
	    struct sockaddr_in6 source;

	    if ((sndsock6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
	    {
		perror("netselect: socket");
		if (errno == EPERM) {
		    fprintf(stderr, "You should be root to run netselect.\n");
		    return 6;
		}
		return 5;
	    }

	    if (setsockopt(sndsock6, IPPROTO_IPV6, IPV6_V6ONLY,
			   &sock_v6_only, sizeof(int)) < 0)
	    {
		perror("setsockopt with IPV6_V6ONLY");
		return 1;
	    }

	    memset(&source, 0, sizeof(struct sockaddr_in6));
	    source.sin6_family = AF_INET6;
	    source.sin6_port = htons(ident);
	    memcpy(&source.sin6_addr, &in6addr_any, sizeof(struct in6_addr));

	    if (bind(sndsock6, (struct sockaddr *)&source, sizeof(source)) < 0)
	    {
		perror("bind");
		return 1;
	    }
	}
    }

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
		    if (host->addr.ss_family == AF_INET
		     || host->addr.ss_family == AF_INET6)
		    {
			if (host->addr.ss_family == AF_INET)
			{
			    if ( use_icmp )
				send_icmp_probe(host->seq, ttl, &icmppacket, host);
			    else
				send_probe(host->seq, ttl, &udppacket, host);
			}
			else
			{
			    if ( use_icmp )
				send_icmp6_probe(host->seq, ttl, &icmp6packet, host);
			    else
				send_probe6(host->seq, ttl, &udppacket6, host);
			}
			endcount = hostcount;
			sent_one = 1;
		    }
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
	if ((host = wait_for_reply(hosts, numhosts, delay)) != NULL)
	{
	    gettimeofday(&now, &tz);
	    delay = 0;

	    if (verbose >= 3)
		fprintf(stderr, "%-35s  %5u ms  %3d hops - ", host->shortname,
		       (unsigned)deltaT(&host->send_time, &now),
		       choose_ttl(host));

	    port_unreachable = 0;
	    other_unreachable = 0;
	    if (host->code == -1)
	    {
		if (verbose >= 3)
		    fprintf(stderr, "HIGHER");
		else if (verbose >= 1)
		    fprintf(stderr, ".");
		if (choose_ttl(host) >= host->hops_less_than)
		    host->hops_less_than = choose_ttl(host) + 1;
		host->hops_more_than = choose_ttl(host);
		host->retries = 0;
		host->num_out--;
	    }
	    else if (host->addr.ss_family == AF_INET)
	    {
		switch (host->code - 1)
		{
		case ICMP_UNREACH_PORT:
		    port_unreachable = 1;
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
		    other_unreachable = 1;
		    break;
		}
	    }
	    else if (host->addr.ss_family == AF_INET6)
	    {
		switch (host->code - 1)
		{
		case ICMP6_DST_UNREACH_NOPORT:
		    port_unreachable = 1;
		    break;

		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
		    other_unreachable = 1;
		    break;
		}
	    }

	    if (port_unreachable)
	    {
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
	    }
	    else if (other_unreachable)
	    {
		if (verbose >= 3)
		    fprintf(stderr, "unreachable!\n");
		if (!host->invalid)
		    validhosts--;
		host->invalid = 1;
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

static inline int in6_addr_cmp(struct in6_addr *a, struct in6_addr *b)
{
    return memcmp(&a->s6_addr, &b->s6_addr, 16);
}

/* 
 * when the newly-created objects are freed, we try to free(hostname)...
 * so make sure it's already dynamically allocated when you call this
 * function!
 */
static HostData *add_host(HostData *hosts, int *numhosts,
			  char *hostname, struct sockaddr *addr,
			  int max_ttl)
{
    HostData *host;
    
    if (addr)
    {
	int hcount;
	sa_family_t family = ((struct sockaddr_storage *)addr)->ss_family;
	struct in_addr *addr4, *haddr4;
	struct in6_addr *addr6, *haddr6;

	if ((family != AF_INET  && family   != AF_INET6)
	 || (family == AF_INET  && addr_fam == AF_INET6)
	 || (family == AF_INET6 && addr_fam == AF_INET ))
        {
	    if (verbose >= 1)
		fprintf(stderr, "\nUnsupported address family %hu for host %s address\n",
			family, hostname);
	    return hosts;
        }

	if (family == AF_INET)
	    addr4 = &((struct sockaddr_in  *)addr)->sin_addr;
	else
	    addr6 = &((struct sockaddr_in6 *)addr)->sin6_addr;

	for (hcount = 0, host = hosts; hcount < *numhosts; hcount++, host++)
	{
	    if (host->invalid || host->addr.ss_family != family)
		continue;

	    if (family == AF_INET)
		haddr4 = &((struct sockaddr_in  *)&host->addr)->sin_addr;
	    else
		haddr6 = &((struct sockaddr_in6 *)&host->addr)->sin6_addr;

	    if ((family == AF_INET  && haddr4->s_addr == addr4->s_addr)
	     || (family == AF_INET6 && in6_addr_cmp(haddr6, addr6) == 0))
	    {
		if (verbose >= 1)
		{
		    char txt[INET6_ADDRSTRLEN];
		    fprintf(stderr, "\nDuplicate address %s (%s, %s); keeping only under first name.\n",
			    inet_ntop(family,
				      family == AF_INET ? (void *)addr4 : (void *)addr6,
				      txt, sizeof(txt)),
			    host->hostname, hostname);
		}
		return hosts;
	    }
	}
    }
    
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
	memcpy(&host->addr, addr, sizeof(struct sockaddr_storage));
    else
	host->invalid = 1;
    host->hops_less_than = max_ttl;
    
    return hosts;
}


static char *un_url(char *orig)
{
    char *sptr, *eptr = NULL, *newbuf;
    
    if ((sptr = strstr(orig, "://")) != NULL)
    {
	/* URL formatted, like: http://hostname:port/dir/file */
	sptr += 3; /* skip :// */
	if (*sptr == '[') /* v6 literal address */
	{
	    eptr = strchr(sptr, ']');
	    if (eptr)
		++sptr;
	}
	if (!eptr) eptr = strchr(sptr, ':');
	if (!eptr) eptr = strchr(sptr, '/');
	if (!eptr) eptr = strchr(sptr, 0);
	
    }
    else
    {
	if (*orig == '[')
	{
	    /* quoted v6 literal address in non-URL format */
	    eptr = strchr(orig, ']');
	    if (eptr)
		sptr = orig + 1;
	}

	if (!sptr && (eptr = strchr(orig, ':')) != NULL)
	{
	    /* Could be an IPv6 address */
	    struct sockaddr_storage ss;
	    if (inet_pton(AF_INET6, orig, &ss) != 1)
	    {
		/* FTP formatted, like: ftp.debian.org:/debian/foo */
		sptr = orig;
	    }
	}
    }

    if (sptr)
    {
	newbuf = (char *)malloc(eptr-sptr+1);
	strncpy(newbuf, sptr, eptr-sptr);
	newbuf[eptr-sptr] = 0;
	return newbuf;
    }
    else /* just plain */
	return strdup(orig);
}

static char *fix_url(char *orig, struct sockaddr *addr)
{
    char *pree = NULL, *posts = NULL;
    char addrstr[INET6_ADDRSTRLEN + 2];
    void *src;

    if ((pree = strstr(orig, "://")) != NULL)
    {
	/* URL formatted, like: http://hostname:port/dir/file */
	pree += 3; /* skip :// */
	if (*pree == '[') /* v6 literal address */
	{
	    posts = strchr(pree, ']');
	    if (posts)
		++posts;
	}
	if (!posts) posts = strchr(pree, ':');
	if (!posts) posts = strchr(pree, '/');
	if (!posts) posts = strchr(pree, 0);
    }
    else
    {
	pree = orig;
	if (*pree == '[')
	{
	    /* quoted v6 literal address in non-URL format */
	    posts = strchr(pree, ']');
	    if (posts)
		++posts;
	}
	
	if (!posts)
	{
	    struct sockaddr_storage ss;
	    if (inet_pton(AF_INET6, orig, &ss) != 1)
	    {
		/* FTP formatted, like: ftp.debian.org:/debian/foo */
		posts = strchr(orig, ':');
	    }
	}
    }

    if (addr->sa_family == AF_INET)
	src = &((struct sockaddr_in  *)addr)->sin_addr;
    else
	src = &((struct sockaddr_in6 *)addr)->sin6_addr;

    inet_ntop(addr->sa_family, src, addrstr, sizeof(addrstr));

    if (posts)
    {
	char *newbuf;
	size_t addrlen;
	size_t prelen = pree - orig;
	size_t postlen = strlen(posts);

	/* We want to quote a v6 address in this case */
	if (addr->sa_family == AF_INET6)
	{
	    char quoted_addr[sizeof(addrstr)];
	    sprintf(quoted_addr, "[%s]", addrstr);
	    strcpy(addrstr, quoted_addr);
	}

	addrlen = strlen(addrstr);

	newbuf = (char *)malloc(prelen + addrlen + postlen + 1);

	if (prelen > 0)
	    strncpy(newbuf, orig, prelen);
	strncpy(newbuf + prelen, addrstr, addrlen);
	strncpy(newbuf + prelen + addrlen, posts, postlen);

	return newbuf;
    }
    else /* just plain */
	return strdup(addrstr);
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
	struct sockaddr_storage addr;
    } result;
    
    HostData *hosts = NULL;
    int closed = 0, active = 0, count = 0, max_active = 24;
    int pipes[2];
    time_t start = time(NULL);
    fd_set rfd, wfd, efd;
    struct timeval tv;
    struct addrinfo *hp, hints;
    pid_t pid;
    int err;
    
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

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = addr_fam;
    hints.ai_flags  = AI_ADDRCONFIG;
    
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

		/* try simple IPv4 dotted-quad conversion */
		if (addr_fam != AF_INET6)
		{
		    struct sockaddr_in *addr4 = (struct sockaddr_in *) &result.addr;
		    addr4->sin_family = AF_INET;
		    addr4->sin_addr.s_addr = inet_addr(names[count]);

		    if (addr4->sin_addr.s_addr != INADDR_NONE)
		    {
			write(pipes[1], &result, sizeof(result));
			/* Use this as a flag to not do a lookup */
			result.multi = 1;
		    }
		}

		if (result.multi == 0);
		{
		    /* must actually do the name lookup */
		    char *simplename = un_url(result.hostname);
		    err = getaddrinfo(simplename, NULL, &hints, &hp);
		    free(simplename);
		    
		    if (!err)
		    {
			struct addrinfo *ptr;
			int already_seen_one = 0;

			result.broken = 0;
			for (ptr = hp; ptr; ptr = ptr->ai_next)
			{
			    if ((ptr->ai_family != AF_INET  && ptr->ai_family != AF_INET6)
			     || (ptr->ai_family == AF_INET  && addr_fam == AF_INET6)
			     || (ptr->ai_family == AF_INET6 && addr_fam == AF_INET))
				continue;

			    if (already_seen_one)
				result.multi = 1;

			    memcpy(&result.addr, ptr->ai_addr, ptr->ai_addrlen);
			    write(pipes[1], &result, sizeof(result));
			    if (!already_seen_one)
				already_seen_one = 1;
			}

			freeaddrinfo(hp);
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
					      (struct sockaddr *)&result.addr);
		    else
			newhostname = strdup(result.hostname);
		    
		    hosts = add_host(hosts, numhosts, newhostname,
				     (struct sockaddr *)&result.addr, max_ttl);
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

static void do_sendto(int sockfd, const void *buf, size_t len, HostData *host)
{
    int i;
    i = sendto(sockfd, buf, len, 0, (struct sockaddr *)&host->addr,
	       sizeof(struct sockaddr_storage));
    if (i < 0 || i != len)
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

static void send_probe(int seq, int ttl, OPacket *op, HostData *host)
{
    struct ip *ip = &op->ip;
    struct udphdr *up = &op->udp;
    struct timezone tz;

    op->ip.ip_dst = ((struct sockaddr_in *)&host->addr)->sin_addr;
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
    	fprintf(stderr, "%-35s(UDP)>>\n", host->shortname);

    do_sendto(sndsock, op, sizeof(OPacket), host);
}

static void send_probe6(int seq, int ttl, OPacket6 *op, HostData *host)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&host->addr;
    struct timezone tz;

    op->seq = seq;
    op->ttl = ttl;
    gettimeofday(&op->tv, &tz);

    addr->sin6_port = htons(port + seq);

    if (verbose >= 4)
        fprintf(stderr, "%-35s(UDP6)>>\n", host->shortname);

    if (setsockopt(sndsock6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    {
	perror("setsockopt with IPV6_UNICAST_HOPS");
	return;
    }

    do_sendto(sndsock6, op, sizeof(OPacket6), host);
}

uint16_t
checksum (uint16_t *header, size_t len)
{
    uint32_t sum = 0;
    int i;

    for (i = 0; i < len / sizeof (uint16_t); i++)
        sum += ntohs (header[i]);

    return htons (~((sum >> 16) + (sum & 0xffff)));
}

static void send_icmp_probe(int seq, int ttl, IPacket *op, HostData *host)
{
    struct ip *ip = &op->ip;
    struct icmp *icmp = &op->icmp;
    struct timezone tz;

    op->ip.ip_dst = ((struct sockaddr_in *)&host->addr)->sin_addr;
    op->seq = seq;
    op->ttl = ttl;
    gettimeofday(&op->tv, &tz);

    ip->ip_off = 0;
    ip->ip_hl = sizeof(*ip) >> 2;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_len = 0; /* kernel fills this in */
    ip->ip_ttl = ttl;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(ident + seq);

    icmp->icmp_type= ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = htons (ident);
    icmp->icmp_seq = htons (seq); 
    icmp->icmp_cksum = checksum((void *)icmp, sizeof(IPacket) - sizeof(struct ip)); 

    if (verbose >= 4)
        fprintf(stderr, "%-35s(ICMP)>>\n", host->shortname);
    if (verbose >= 5)
        fprintf(stderr, "ICMP sequence: %i, identifier: %i\n", icmp->icmp_seq, icmp->icmp_id);

    do_sendto(sndsock, op, sizeof(IPacket), host);
}

static void send_icmp6_probe(int seq, int ttl, I6Packet *op, HostData *host)
{
    struct icmp6_hdr *icmp = &op->icmp6;
    struct timezone tz;

    gettimeofday(&op->tv, &tz);

    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_code = 0;
    icmp->icmp6_cksum = 0;
    icmp->icmp6_id = htons (ident);
    icmp->icmp6_seq = htons (seq);

    if (verbose >= 4)
        fprintf(stderr, "%-35s(ICMP6)>>\n", host->shortname);
    if (verbose >= 5)
        fprintf(stderr, "ICMP6 sequence: %i, identifier: %i\n", icmp->icmp6_seq, icmp->icmp6_id);

    if (setsockopt(sndsock6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    {
	perror("setsockopt with IPV6_UNICAST_HOPS");
	return;
    }

    do_sendto(sndsock6, op, sizeof(I6Packet), host);
}


static time_t deltaT(struct timeval *t1p, struct timeval *t2p)
{
    return (t2p->tv_sec - t1p->tv_sec) * 1000
	 + (t2p->tv_usec - t1p->tv_usec) / 1000;
}

static HostData * receive(HostData *hosts, int numhosts, int sock)
{
    u_char inpacket[INPACKET_SIZE];
    struct sockaddr_storage from;
    int cc = 0;
    HostData *host = NULL;
    
#if !defined(__GLIBC__)
    int fromlen = sizeof(from);
#else				/* __GLIBC__ */
    socklen_t fromlen = sizeof(from);
#endif				/* __GLIBC__ */

    cc = recvfrom(sock, inpacket, INPACKET_SIZE, 0,
		  (struct sockaddr *) &from, &fromlen);
    if (cc > 0 &&
	(addr_fam == AF_UNSPEC || from.ss_family == addr_fam))
    {
	if (from.ss_family == AF_INET)
	    host = packet_ok(hosts, numhosts, inpacket, cc,
			     (struct sockaddr_in *)&from);
	else
	    host = packet6_ok(hosts, numhosts, inpacket, cc,
			      (struct sockaddr_in6 *)&from);
    }

    return host;
}

static HostData *wait_for_reply(HostData *hosts, int numhosts,
				       int msec_timeout)
{
    fd_set fds;
    struct timeval wait, start_time;
    struct timezone tz;
    time_t msec_used;
    HostData *host;
    int nfds = -1;
    int sock;

    FD_ZERO(&fds);
    if (addr_fam != AF_INET6)
    {
	FD_SET(rcvsock,  &fds);
	nfds = rcvsock;
    }
    if (addr_fam != AF_INET)
    {
	FD_SET(rcvsock6, &fds);
	if (nfds < rcvsock6)
	    nfds = rcvsock6;
    }
    ++nfds;
    
    gettimeofday(&start_time, &tz);

    for (;;)
    {
	gettimeofday(&wait, &tz);
	msec_used = deltaT(&start_time, &wait);
	if (msec_used > msec_timeout)
	    break;	       /* timed out */
	
	wait.tv_usec = (msec_timeout - msec_used) * 1000;
	wait.tv_sec = 0;
	
	if (select(nfds, &fds, NULL, NULL, &wait) > 0)
	{
	    if (addr_fam == AF_INET)
		sock = rcvsock;
	    else if (addr_fam == AF_INET6)
		sock = rcvsock6;
	    else if (FD_ISSET(rcvsock, &fds))
		sock = rcvsock;
	    else
		sock = rcvsock6;

	    if ((host = receive(hosts, numhosts, sock)) != NULL)
		return host;
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
    struct sockaddr_in *haddr;

    ip = (struct ip *) buf;
    hlen = ip->ip_hl << 2;
    if (cc < hlen + ICMP_MINLEN)
	return 0;
    cc -= hlen;
    icp = (struct icmp *) (buf + hlen);

    type = icp->icmp_type;
    code = icp->icmp_code;

    if (verbose >= 5)
        fprintf(stderr, "Received ICMP type: %i, code: %i, from %s\n", type, code, inet_ntoa(ip->ip_src) );

    if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS)
	|| type == ICMP_UNREACH || type == ICMP_ECHOREPLY )
    {
	struct ip *hip;
	struct udphdr *up;

	hip = &icp->icmp_ip;
	hlen = hip->ip_hl << 2;
	up = (struct udphdr *) ((u_char *) hip + hlen);

	
	for (hcount = 0, host = hosts; hcount < numhosts; hcount++, host++)
	{
	    if (host->invalid || host->addr.ss_family != AF_INET) continue;

	    haddr = (struct sockaddr_in *)&host->addr;

            /* Valid ICMP echo reply packet */
            if ( type == ICMP_ECHOREPLY &&
                 ip->ip_src.s_addr == haddr->sin_addr.s_addr &&
                 icp->icmp_id == htons(ident) && 
                 icp->icmp_seq == htons(host->seq) )
            {
		host->code = ICMP_UNREACH_PORT + 1; /* Behave like if a UDP packet was received even though we used ICMP */
		return host;
            }
            /* Time exceeded reply to an ICMP echo request */
            if ( type == ICMP_TIMXCEED &&
                 hip->ip_dst.s_addr == haddr->sin_addr.s_addr &&
                 hip->ip_id == htons(ident+host->seq) )
            {
		host->code = -1; 
		return host;
            }
	    
            /* Valid reply to an UDP probe packet */
	    if (hlen + 12 <= cc && hip->ip_p == IPPROTO_UDP &&
		up->uh_sport == htons(ident) &&
		up->uh_dport == htons(port + host->seq) &&
		hip->ip_dst.s_addr == haddr->sin_addr.s_addr)
	    {
		host->code = (type == ICMP_TIMXCEED ? -1 : code + 1);
		return host;
	    }
	}
    }

    if (verbose >= 3)
        fprintf(stderr, "received an unknown packet!\n"); 
    return NULL;
}

static HostData *packet6_ok(HostData *hosts, int numhosts,
				  u_char * buf, int cc,
				  struct sockaddr_in6 *from)
{
    u_char type, code;
    struct icmp6_hdr *icp;
    HostData *host;
    int hcount;

    if (cc < sizeof(struct icmp6_hdr))
	return NULL;

    icp = (struct icmp6_hdr *) buf;

    type = icp->icmp6_type;
    code = icp->icmp6_code;

    if (verbose >= 5)
    {
	char txt[INET6_ADDRSTRLEN];
        fprintf(stderr, "Received ICMP6 type: %i, code: %i, from %s\n", type, code,
		inet_ntop(AF_INET6, &from->sin6_addr, txt, sizeof(txt)) );
    }

    if ((type == ICMP6_TIME_EXCEEDED && code == ICMP6_TIME_EXCEED_TRANSIT)
	|| type == ICMP6_DST_UNREACH || type == ICMP6_ECHO_REPLY )
    {
	struct ip6_hdr *hip;
	int invoke_len;

	hip = (struct ip6_hdr *) (icp + 1);

	if (type != ICMP6_ECHO_REPLY)
	{
	    if (cc < (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)))
		return NULL;

	    /* Check packet is as big as the following code assumes */
	    switch (hip->ip6_nxt)
	    {
	    case IPPROTO_ICMPV6:
		invoke_len = sizeof(struct icmp6_hdr);
		break;
	    case IPPROTO_UDP:
		invoke_len = sizeof(struct udphdr);
		break;
	    default:
		return NULL;
	    };

	    if (cc < (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + invoke_len))
		return NULL;
	}

	for (hcount = 0, host = hosts; hcount < numhosts; hcount++, host++)
	{
	    struct sockaddr_in6 *haddr;

	    if (host->invalid || host->addr.ss_family != AF_INET6) continue;

	    haddr = (struct sockaddr_in6 *)&host->addr;

            /* Valid ICMP echo reply packet */
            if ( type == ICMP6_ECHO_REPLY &&
		 in6_addr_cmp(&from->sin6_addr, &haddr->sin6_addr) == 0 &&
                 icp->icmp6_id == htons(ident) &&
                 icp->icmp6_seq == htons(host->seq) )
            {
		host->code = ICMP6_DST_UNREACH_NOPORT + 1; /* Behave like if a UDP packet was received even though we used ICMP */
		return host;
            }
            /* Time exceeded reply to an ICMP echo request */
            if ( type == ICMP6_TIME_EXCEEDED &&
		 hip->ip6_nxt == IPPROTO_ICMPV6 &&
                 in6_addr_cmp(&hip->ip6_dst, &haddr->sin6_addr) == 0 &&
		 ((struct icmp6_hdr *)(hip + 1))->icmp6_id == htons(ident+host->seq) )
	    {
		host->code = -1;
		return host;
	    }

            /* Valid reply to an UDP probe packet */
	    if ( hip->ip6_nxt == IPPROTO_UDP &&
		 in6_addr_cmp(&hip->ip6_dst, &haddr->sin6_addr) == 0 &&
		 ((struct udphdr *)(hip + 1))->uh_sport == htons(ident) &&
		 ((struct udphdr *)(hip + 1))->uh_dport == htons(port + host->seq) )
	    {
		host->code = (type == ICMP6_TIME_EXCEEDED ? -1 : code + 1);
		return host;
	    }
	}
    }

    if (verbose >= 3)
        fprintf(stderr, "received an unknown v6 packet!\n");
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
	    "Usage: netselect [-v|-vv|-vvv] [-I] [-m max_ttl] [-s servers] "
	    "[-t min_tries] host ...\n");
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

