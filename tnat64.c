/*

    TNAT64 - Wrapper library for redirecting IPv4 connections to NAT64
    Copyright (C) 2011 Andrej Shadura
    Based on original code of TSOCKS, copyright (C) 2000 Shaun Clowes

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
    MA 02110-1301, USA.

*/

/* PreProcessor Defines */
#include <config.h>

#ifdef USE_GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Global configuration variables */
static const char *progname = "libtnat64";   /* Name used in err msgs    */

/* Header Files */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <common.h>
#include <stdarg.h>
#include <parser.h>

/* Mask which covers at least up to SOCK_MASK-1.  The
 *  * remaining bits are used as flags.
 *  per Linux kernel 2.6.* */
#define SOCK_TYPE_MASK 0xf

/* Global Declarations */
static int (*realsocket) (SOCKET_SIGNATURE);
static int (*realconnect) (CONNECT_SIGNATURE);
static int (*realgetpeername) (GETPEERNAME_SIGNATURE);
static int (*realgetsockname) (GETSOCKNAME_SIGNATURE);
static struct parsedfile *config;
static int suid = 0;
static char *conffile = NULL;

static struct in6_addr ipv4mapped;

static int current_af = AF_INET6;

/* Exported Function Prototypes */
void _init(void);
int socket(SOCKET_SIGNATURE);
int connect(CONNECT_SIGNATURE);
int getpeername(GETPEERNAME_SIGNATURE);
int getsockname(GETSOCKNAME_SIGNATURE);

/* Private Function Prototypes */
static int get_config();
static int get_environment();

void _init(void)
{
#ifdef USE_OLD_DLSYM
    void *lib;
#endif

    /* We could do all our initialization here, but to be honest */
    /* most programs that are run won't use our services, so     */
    /* we do our general initialization on first call            */

    /* Determine the logging level */
    suid = (getuid() != geteuid());

#ifndef USE_OLD_DLSYM
    realconnect = dlsym(RTLD_NEXT, "connect");
    realsocket = dlsym(RTLD_NEXT, "socket");
    realgetpeername = dlsym(RTLD_NEXT, "getpeername");
    realgetsockname = dlsym(RTLD_NEXT, "getsockname");
#else
    lib = dlopen(LIBCONNECT, RTLD_LAZY);
    realconnect = dlsym(lib, "connect");
    realsocket = dlsym(lib, "socket");
    realgetpeername = dlsym(lib, "getpeername");
    realgetsockname = dlsym(lib, "getsockname");
    dlclose(lib);
#endif
    inet_pton(AF_INET6, "::ffff:0.0.0.0", &ipv4mapped);

    get_environment();
}

static int get_environment()
{
    static int done = 0;
    int loglevel = MSGERR;
    char *logfilename = NULL;
    char *env;

    if (done)
        return (0);

    /* Determine the logging level */
#ifndef ALLOW_MSG_OUTPUT
    set_log_options(MSGNONE, progname, NULL, 0);
#else
    if ((env = getenv("TNAT64_DEBUG")))
        loglevel = atoi(env);
    if (((env = getenv("TNAT64_DEBUG_FILE"))) && !suid)
        logfilename = env;
    set_log_options(loglevel, progname, logfilename, 1);
#endif

    done = 1;

    return (0);
}

static int get_config()
{
    static int done = 0;

    if (done)
        return (0);

    /* Determine the location of the config file */
#ifdef ALLOW_ENV_CONFIG
    if (!suid)
        conffile = getenv("TNAT64_CONF_FILE");
#endif

    /* Read in the config file */
    config = malloc(sizeof(*config));
    if (!config)
        return (0);
    read_config(conffile, config);
    if (config->paths)
        show_msg(MSGDEBUG, "First lineno for first path is %d\n", config->paths->lineno);

    done = 1;

    return (0);

}

int socket(SOCKET_SIGNATURE)
{
    /* If the real socket doesn't exist, we're stuffed */
    if (realsocket == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: socket\n");
        return (-1);
    }
    if ((__domain == AF_INET) && ((__type & SOCK_TYPE_MASK) == SOCK_STREAM))
    {
        int sock = realsocket(AF_INET6, __type, __protocol);

        if (sock < 0) {
            return sock;
        }

        // Now set this IPv6 socket to allow both IPv6 and IPv4 connections. 
        // Most OSes do that by default, but not all. 
        int no = 0;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&no, sizeof(no)) < 0) {
            show_msg(MSGDEBUG, "Failed to disable IPV6_V6ONLY for socket %d: error %d (%s)\n", sock, errno, strerror(errno));
        }

        return sock;
    }
    else
    {
        return realsocket(__domain, __type, __protocol);
    }
}

struct in6_addr put_ipv4_into_prefix(struct prefixent *prefix, struct in_addr ipv4_address) {
    struct in6_addr retval;

    // Copy the prefix
    memcpy(&retval, &(prefix->prefix), 16);

    // Determine the suffix size from the prefix size (RFC6052, 2.2)
    int suffix_size = 0;
    switch (prefix->prefix_size) {
        case 32:
            suffix_size = 7; break;
        case 40:
            suffix_size = 6; break;
        case 48:
            suffix_size = 5; break;
        case 56:
            suffix_size = 4; break;
        case 64:
            suffix_size = 3; break;
        case 96:
        case 128:
        default:
            suffix_size = 0; break;
    }

    // Copy over the suffix:
    for (int i = 0; i < suffix_size; i++) {
        retval.s6_addr[15-i] = (prefix->suffix).s6_addr[15-i];
    }

    // Now add the IPv4 address at the correct location - overwriting the suffix if necessary.

    switch (prefix->prefix_size) {
        case 32:
            memcpy(retval.s6_addr+4, &ipv4_address.s_addr, 4);
            break;
        case 40:
            memcpy(retval.s6_addr+5, &ipv4_address.s_addr, 3);
            memcpy(retval.s6_addr+9, (char *)&ipv4_address.s_addr + 3, 1);
            break;
        case 48:
            memcpy(retval.s6_addr+6, &ipv4_address.s_addr, 2);
            memcpy(retval.s6_addr+9, (char *)&ipv4_address.s_addr + 2, 2);
            break;
        case 56:
            memcpy(retval.s6_addr+7, &ipv4_address.s_addr, 1);
            memcpy(retval.s6_addr+9, (char *)&ipv4_address.s_addr + 1, 3);
            break;
        case 64:
            memcpy(retval.s6_addr+9, &ipv4_address.s_addr, 4);
            break;
        case 96:
            memcpy(retval.s6_addr+12, &ipv4_address.s_addr, 4);
            break;
        case 128:
            // No replacement necessary, route all IPv4 packets to this IPv6 address.
            break;
    }

    return retval;

}

struct in_addr get_ipv4_from_prefix(struct prefixent *prefix, struct in6_addr ipv6_address) {
    struct in_addr retval = {};

    switch (prefix->prefix_size) {
        case 32:
            memcpy(&retval.s_addr, ipv6_address.s6_addr + 4, 4);
            return retval;
        case 40:
            memcpy(        &retval.s_addr,     ipv6_address.s6_addr + 5, 3);
            memcpy((char *)&retval.s_addr + 3, ipv6_address.s6_addr + 9, 1);
            return retval;
        case 48:
            memcpy(        &retval.s_addr,     ipv6_address.s6_addr + 6, 2);
            memcpy((char *)&retval.s_addr + 2, ipv6_address.s6_addr + 9, 2);
            return retval;
        case 56:
            memcpy(        &retval.s_addr,     ipv6_address.s6_addr + 7, 1);
            memcpy((char *)&retval.s_addr + 1, ipv6_address.s6_addr + 9, 3);
            return retval;
        case 64:
            memcpy(&retval.s_addr, ipv6_address.s6_addr + 9, 4);
            return retval;
        case 96:
            memcpy(&retval.s_addr, ipv6_address.s6_addr + 12, 4);
            return retval;
        case 128:
        default:
            // IP unknown, just set 0.0.0.0
            memset(&retval.s_addr, 0, 4);
            return retval;
    }
}

int connect(CONNECT_SIGNATURE)
{
    struct sockaddr_in *connaddr;
    char addrbuffer[INET6_ADDRSTRLEN];
    struct sockaddr_in6 dest_address6;
    int sock_type = -1;
    socklen_t sock_type_len = sizeof(sock_type);
    struct prefixent *path;
    int failed = 0;

    /* If the real connect doesn't exist, we're stuffed */
    if (realconnect == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: connect\n");
        return (-1);
    }

    show_msg(MSGDEBUG, "Got connection request\n");

    connaddr = (struct sockaddr_in *)__addr;

    /* Get the type of the socket */
    getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *)&sock_type, &sock_type_len);

    /* If this isn't an INET socket for a TCP stream we can't  */
    /* handle it, just call the real connect now               */
    if ((connaddr->sin_family != AF_INET) || (sock_type != SOCK_STREAM))
    {
        show_msg(MSGDEBUG, "Connection isn't a TCP/IPv4 stream, ignoring\n");
        return realconnect(__fd, __addr, __len);
    }

    /* If we haven't initialized yet, do it now */
    get_config();

    show_msg(MSGDEBUG, "Got connection request for socket %d to " "%s:%d\n", __fd, inet_ntoa(connaddr->sin_addr), ntohs(connaddr->sin_port));

    /* If the address is local call realconnect */
    if (!(is_local(config, &(connaddr->sin_addr))))
    {
        show_msg(MSGDEBUG, "Connection for socket %d is local\n", __fd);
        /* Rewrite to an IPv6 socket connect */
        dest_address6.sin6_family = AF_INET6;
        dest_address6.sin6_port = connaddr->sin_port;
        dest_address6.sin6_flowinfo = 0;
        dest_address6.sin6_scope_id = 0;
        memcpy(&dest_address6.sin6_addr, &ipv4mapped, sizeof(struct in6_addr));
        memcpy(&dest_address6.sin6_addr.s6_addr[NAT64PREFIXLEN], &connaddr->sin_addr, sizeof(struct in_addr));
        if (inet_ntop(AF_INET6, &dest_address6.sin6_addr, addrbuffer, sizeof(addrbuffer)))
        {
            show_msg(MSGDEBUG, "Connecting to local IPv4-mapped IPv6 address %s...\n", addrbuffer);
        }

        return realconnect(__fd, (struct sockaddr *)&dest_address6, sizeof(struct sockaddr_in6));
    }

    /* Don't retry more than once */
    while (failed < 2)
    {
        if (current_af == AF_INET)
        {
            /* Construct the IPv4-mapped IPv6 address */
            dest_address6.sin6_family = AF_INET6;
            dest_address6.sin6_port = connaddr->sin_port;
            dest_address6.sin6_flowinfo = 0;
            dest_address6.sin6_scope_id = 0;
            memcpy(&dest_address6.sin6_addr, &ipv4mapped, sizeof(struct in6_addr));
            memcpy(&dest_address6.sin6_addr.s6_addr[NAT64PREFIXLEN], &connaddr->sin_addr, sizeof(struct in_addr));
            if (inet_ntop(AF_INET6, &dest_address6.sin6_addr, addrbuffer, sizeof(addrbuffer)))
            {
                show_msg(MSGDEBUG, "Trying IPv4-mapped IPv6 address %s...\n", addrbuffer);
            }

            if (realconnect(__fd, (struct sockaddr *)&dest_address6, sizeof(struct sockaddr_in6)) == 0)
            {
                show_msg(MSGDEBUG, "Success.\n");
                return 0;
            }
            if (errno != ENETUNREACH)
            {
                show_msg(MSGDEBUG, "Error: %d (%s)\n", errno, strerror(errno));
                return -1;
            }
            else
            {
                show_msg(MSGDEBUG, "Error: %d (%s)\n", errno, strerror(errno));
                current_af = AF_INET6;
                failed++;
            }
        }
        else
        {
            /* Ok, so its not local, we need a path to the net */
            pick_prefix(config, &path, &(connaddr->sin_addr), ntohs(connaddr->sin_port));

            show_msg(MSGDEBUG, "Picked prefix %s for connection\n", (path->address ? path->address : "(Not Provided)"));
            if (path->address == NULL)
            {
                if (path == &(config->defaultprefix))
                    show_msg(MSGERR, "Connection needs to be made " "via default prefix but " "the default prefix has not " "been specified\n");
                else
                    show_msg(MSGERR, "Connection needs to be made " "via path specified at line " "%d in configuration file but " "the prefix has not been " "specified for this path\n", path->lineno);

            }
            else
            {
                /* Construct the NAT64-ed address */
                dest_address6.sin6_family = AF_INET6;
                dest_address6.sin6_port = connaddr->sin_port;
                dest_address6.sin6_flowinfo = 0;
                dest_address6.sin6_scope_id = 0;

                struct in6_addr dest = put_ipv4_into_prefix(path, connaddr->sin_addr);
                memcpy(&dest_address6.sin6_addr, &dest, sizeof(struct in6_addr));

                if (inet_ntop(AF_INET6, &dest_address6.sin6_addr, addrbuffer, sizeof(addrbuffer)))
                {
                    show_msg(MSGDEBUG, "Trying IPv6 address %s...\n", addrbuffer);
                }

                if (realconnect(__fd, (struct sockaddr *)&dest_address6, sizeof(struct sockaddr_in6)) == 0)
                {
                    return 0;
                }
                if (errno != ENETUNREACH)
                {
                    return -1;
                }
                else
                {
                    current_af = AF_INET;
                    failed++;
                }
            }


        }
    }


    /* If we haven't found a valid NAT64 prefix to route the connection, we return ECONNREFUSED */
    errno = ECONNREFUSED;
    return -1;
}

static char afs[][16] = {
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6"
};

int getpeername(GETPEERNAME_SIGNATURE)
{
    /* If the real getpeername doesn't exist, we're stuffed */
    if (realgetpeername == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: getpeername\n");
        return (-1);
    }

    /* If we haven't initialized yet, do it now */
    get_config();

    show_msg(MSGDEBUG, "Got getpeername call for socket %d\n", __fd);
    socklen_t needlen = *__len;
    int ret = realgetpeername(__fd, __addr, &needlen);
    if (ret < 0)
    {
        return ret;
    }

    if (*__len < sizeof(struct sockaddr_in))
    {
        *__len = sizeof(struct sockaddr_in);
        errno = EINVAL;
        return -1;
    }

    /* TODO: AF_INET6 is not necessarily 10, this debug print is wrong */
    if (__addr->sa_family <= 10) {
        show_msg(MSGDEBUG, "Address family is %s\n", afs[__addr->sa_family]);
    }

    if (__addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 realpeer;
        socklen_t realpeerlen = sizeof(realpeer);
        int ret = realgetpeername(__fd, (struct sockaddr *)&realpeer, &realpeerlen);
        if (ret < 0) {
            return ret;
        }
        if ((!memcmp(&realpeer.sin6_addr, &ipv4mapped, NAT64PREFIXLEN)) || (check_prefix(config, &realpeer.sin6_addr)))
        {
            struct sockaddr_in * result;
            result = (struct sockaddr_in *)__addr;
            result->sin_family = AF_INET;
            result->sin_port = realpeer.sin6_port;

            // Now that we're supporting different prefix lengths, we can't just take the lower 32 bits anymore. 
            // Call check_prefix, have that return the *actual* prefix, so we know the prefix length to extract the IPv4.

            struct prefixent * pfx = check_prefix(config, &realpeer.sin6_addr);

            // Extract the IPv4 from that prefix.
            if (pfx) {
                struct in_addr ipv4 = get_ipv4_from_prefix(pfx, realpeer.sin6_addr);
                memcpy(&result->sin_addr, &ipv4, sizeof(struct in_addr));
            }
            else {
                // Can this even happen? Fallback so we don't crash.
                memset(&result->sin_addr, 0, 4);
            }

            *__len = sizeof(struct sockaddr_in);
            return ret;
        }
    }
    return ret;
}

int getsockname(GETSOCKNAME_SIGNATURE)
{
    /* If the real getsockname doesn't exist, we're stuffed */
    if (realgetsockname == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: getsockname\n");
        return (-1);
    }
    if (realgetpeername == NULL)
    {
        show_msg(MSGERR, "Unresolved symbol: getpeername\n");
        return (-1);
    }

    /* If we haven't initialized yet, do it now */
    get_config();

    show_msg(MSGDEBUG, "Got getsockname call for socket %d\n", __fd);
    socklen_t needlen = *__len;
    int ret = realgetsockname(__fd, __addr, &needlen);
    if (ret < 0)
    {
        return ret;
    }

    if (*__len < sizeof(struct sockaddr_in))
    {
        *__len = sizeof(struct sockaddr_in);
        errno = EINVAL;
        return -1;
    }

    /* TODO: AF_INET6 is not necessarily 10, this debug print is wrong */
    if (__addr->sa_family <= 10) {
        show_msg(MSGDEBUG, "Address family is %s\n", afs[__addr->sa_family]);
    }

    if (__addr->sa_family == AF_INET6)
    {
        struct sockaddr_in6 realsock;
        socklen_t realsocklen = sizeof(realsock);
        int ret = realgetsockname(__fd, (struct sockaddr *)&realsock, &realsocklen);
        if (ret < 0) {
            return ret;
        }
        if ((!memcmp(&realsock.sin6_addr, &ipv4mapped, NAT64PREFIXLEN)) || (check_prefix(config, &realsock.sin6_addr)))
        {
            struct sockaddr_in * result;
            result = (struct sockaddr_in *)__addr;
            result->sin_family = AF_INET;
            result->sin_port = realsock.sin6_port;
            memcpy(&result->sin_addr, &realsock.sin6_addr.s6_addr[12], sizeof(struct in_addr));
            *__len = sizeof(struct sockaddr_in);
            return ret;
        }
    }
    return ret;
}

