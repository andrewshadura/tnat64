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
#include <sys/resource.h>
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

static void * socket_fd_flags = 0;
static int socket_fd_max = 0;

/* 
 * socket_fd_flags is an array with four bits for each possible socket. 
 * Upon first usage, getrlimit is executed to find out the maximum 
 * number of sockets, then the array is allocated for that size. 
 * 
 * This array is used to store if a particular socket always was an IPv6
 * socket or if it was "upgraded" from an IPv4 socket to an IPv6 socket. 
 * 
 * This is needed so that functions like getpeername know if they can return
 * an IPv6 address to the IPv6-aware application (if the socket was opened)
 * as an IPv6 socket, or if the application intended to open an IPv4 socket
 * and thus expects an IPv4 peer address. 
 */

/* Exported Function Prototypes */
void _init(void);
int socket(SOCKET_SIGNATURE);
int connect(CONNECT_SIGNATURE);
int getpeername(GETPEERNAME_SIGNATURE);
int getsockname(GETSOCKNAME_SIGNATURE);

/* Private Function Prototypes */
static int get_config();
static int get_environment();

// This flag is set if the socket was requested by the application 
// as an IPv4 socket and we upgraded it to IPv6.
#define TNAT_FLAG_SOCK_UPGRADED_TO_IPV6 (1 << 0)     
#define TNAT_FLAG_UNUSED_1 (1 << 1)
#define TNAT_FLAG_UNUSED_2 (1 << 2)
#define TNAT_FLAG_UNUSED_3 (1 << 3)

/// returns flags (up to 4 bits) for the given socket.
int get_custom_fd_flags(int fd) {
   
    // Any socket that doesn't have an entry in this array
    // can't have any flags. Same for if the array hasn't been
    // allocated yet.
    if (socket_fd_flags == 0 || fd >= socket_fd_max) return 0;

    int idx = fd/2;
    char * arr = socket_fd_flags;
    arr += idx;

    if (fd % 2 == 0) {
        return (*arr & 0xF0) >> 4;
    }
    return (*arr & 0x0F);  
}

int allocate_or_resize_flag_array() {
    /* We need that flag array (socket_fd_flags) to store some information
    about each allocated socket. Check the socket limit for the process, 
    then allocate an array. */

    // Moving this allocation to usage time (called by set_custom_fd_flags)
    // instead of performing it at application start means that we don't
    // waste time and memory allocating this for IPv6-native applications
    // that won't use the NAT64.
    // Also, it keeps allocation and reallocation/resizing code at the same place.

    struct rlimit limit;
    getrlimit(RLIMIT_NOFILE, &limit);
    show_msg(MSGDEBUG, "Checking file descriptor limits - current limit: %d, max limit: %d\n", limit.rlim_cur, limit.rlim_max);

    int needed_size = (limit.rlim_max / 2) + 1;


    if (socket_fd_flags == 0) {
        // Array hasn't been allocated yet (1st call since start), allocate it.

        show_msg(MSGDEBUG, "Perform initial flag array allocation (size %d bytes, %d entries)\n", needed_size, limit.rlim_max);
        // Perform initial allocation.
        socket_fd_flags = calloc(needed_size, 1); 
        if (socket_fd_flags == 0) {
            show_msg(MSGERR, "Failed to allocate buffer for the flag array - calloc returned 0!\n");
            return (-1);
        }
        socket_fd_max = limit.rlim_max;
        show_msg(MSGDEBUG, "Allocated the flag buffer to size of %d (%d entries)!\n", needed_size, limit.rlim_max);
    }
    else if (socket_fd_max < limit.rlim_max) {
        show_msg(MSGDEBUG, "Perform reallocation of the flag array (old size %d entries, new size %d entries)\n", socket_fd_max, limit.rlim_max);
        // Array is already allocated but too small, make it larger
        void * new_allocation = realloc(socket_fd_flags, needed_size);
        if (new_allocation == 0) {
            show_msg(MSGERR, "Failed to re-allocate the flag buffer to new size - realloc returned 0!\n");
            return (-1);
        }
        int old_size = (socket_fd_max / 2) + 1;

        socket_fd_flags = new_allocation;
        socket_fd_max = limit.rlim_max;

        // Now set the new space to 0:
        if (needed_size > old_size) {
            memset(new_allocation + old_size, 0, needed_size - old_size);
        }

        show_msg(MSGDEBUG, "Re-allocated the flag buffer to new size of %d (%d entries)!\n", needed_size, limit.rlim_max);
    }  
    else {
        show_msg(MSGDEBUG, "Array re-allocation not needed.\n");
    }

    return 0;     
}

int set_custom_fd_flags(int fd, int flags) {

    if (socket_fd_flags == 0 || fd >= socket_fd_max) {
        // If this happens, we need to allocate (or resize) the flag array.
        allocate_or_resize_flag_array();
    }

    if (socket_fd_flags == 0 || fd >= socket_fd_max) {
        // This should never happen, but if it does, let's not crash.
        show_msg(MSGERR, "Allocation failed, or application used a file descriptor larger than the kernel allows - abort.\n");
        return (-1);
    }

    if (flags > 15 || flags < 0) {
        show_msg(MSGWARN, "Tried to set invalid flag %d for fd %d\n", flags, fd);
        return (-2);
    } 

    int idx = fd/2;
    char * arr = socket_fd_flags;
    arr += idx;

    if (fd % 2 == 0) {
        *arr = (flags << 4) | (*arr & 0x0F);
    }
    else {
        *arr = (*arr & 0xF0) | flags;
    }

    return flags;


}

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

        // Store the socket in our custom array so we know that that's an IPv4 
        // socket we forcibly upgraded to IPv6. 
        int flag_ret = set_custom_fd_flags(sock, TNAT_FLAG_SOCK_UPGRADED_TO_IPV6);
        if (flag_ret < 0) {
            show_msg(MSGWARN, "Setting a custom flag for the socket %d failed with error %d\n", sock, flag_ret);
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
        int sock = realsocket(__domain, __type, __protocol);
        if (sock >= 0 && socket_fd_flags != 0) {
            // Only needed if we got a socket and the array is already allocated.
            int flag_ret = set_custom_fd_flags(sock, 0);
            if (flag_ret < 0) {
                show_msg(MSGWARN, "Setting a custom flag for the socket %d failed with error %d\n", sock, flag_ret);
            }
        }
        return sock;
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
    if (getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *)&sock_type, &sock_type_len) < 0) {
        show_msg(MSGERR, "Can't figure out socket type! - error %d (%s)\n", errno, strerror(errno));
        return (-1);
    }

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

        // Check if this socket can send data to IPv4 addresses or if that's disabled: 
        int sockopt = -1;
        socklen_t len = sizeof(sockopt);
        if (getsockopt(__fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&sockopt, &len) < 0) {
            show_msg(MSGWARN, "Can't figure out if this IPv6 socket supports IPv4, assume yes - error %d (%s)\n", errno, strerror(errno));
        }

        if (sockopt != 1) {
            // IPv6 socket supports IPv4 because the V6ONLY flag is not 1. 

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
        else {
            show_msg(MSGWARN, "Aborting local IPv4 connection because socket doesn't support it.\n");

            if (connaddr->sin_addr.s_addr == htonl(0x7f000001)) {
                // Application wants to connect to 127.0.0.1 but the socket doesn't support IPv4 connections. 
                // Why not try to connect to ::1 instead? Better than returning an error ...

                show_msg(MSGWARN, "Trying to connect to [::1] instead of 127.0.0.1 ...\n");
                dest_address6.sin6_family = AF_INET6;
                dest_address6.sin6_port = connaddr->sin_port;
                dest_address6.sin6_flowinfo = 0;
                dest_address6.sin6_scope_id = 0;
                inet_pton(AF_INET6, "::1", &dest_address6.sin6_addr);
                return realconnect(__fd, (struct sockaddr *)&dest_address6, sizeof(struct sockaddr_in6));
            }
        }
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
                memcpy(&dest_address6.sin6_addr, &path->prefix, sizeof(struct in6_addr));
                memcpy(&dest_address6.sin6_addr.s6_addr[12], &connaddr->sin_addr, sizeof(struct in_addr));
                if (inet_ntop(AF_INET6, &dest_address6.sin6_addr, addrbuffer, sizeof(addrbuffer)))
                {
                    show_msg(MSGDEBUG, "Trying IPv6 address %s...\n", addrbuffer);
                }

                if (realconnect(__fd, (struct sockaddr *)&dest_address6, sizeof(struct sockaddr_in6)) == 0)
                {
                    show_msg(MSGDEBUG, "Connected successfully.\n");
                    return 0;
                }
                if (errno != ENETUNREACH)
                {
                    show_msg(MSGDEBUG, "Connect failed with errno=%d\n", errno);
                    return -1;
                }
                else
                {
                    // Connection to the IPv6 address failed for some reason. 
                    // Increment the error counter
                    failed++; 

                    // Now check if the IPv6 socket allows connecting to IPv4 targets - 
                    // if so, try to connect over IPv4.

                    // If the socket does NOT support IPv4 destinations, there's
                    // no need to try to connect to one - just return an error.

                    int sockopt = -1;
                    socklen_t len = sizeof(sockopt);
                    if (getsockopt(__fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&sockopt, &len) < 0) {
                        show_msg(MSGWARN, "Can't figure out if this IPv6 socket supports IPv4, assuming it does (error %d: %s)\n", errno, strerror(errno));
                    }

                    if (sockopt != 1) {
                        // IPv6 socket supports IPv4 because the V6ONLY flag is not 1. 
                        current_af = AF_INET;
                    }
                    else {
                        return -1;
                    }
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

    int sock_flags = get_custom_fd_flags(__fd);

    if (sock_flags < 0) {
        show_msg(MSGERR, "Failed to query socket flags for fd %d, err=%d\n", __fd, sock_flags);
        // Assume it's a normal socket, though this should never happen.
        sock_flags = 0;
    }
    if (sock_flags >= 0 && (!(sock_flags & TNAT_FLAG_SOCK_UPGRADED_TO_IPV6))) {
        // TNAT_FLAG_SOCK_UPGRADED_TO_IPV6 is not set - this means that whatever
        // that socket is, we don't care, it's not something we need to modify.
        // So we can call the original getpeername.
        show_msg(MSGDEBUG, "None of our modded sockets, call real getpeername\n");
        return realgetpeername(__fd, __addr, __len);
    }

    struct sockaddr_storage sockaddr_st;
    socklen_t size = sizeof(sockaddr_st);

    int ret = realgetpeername(__fd, (struct sockaddr *)&sockaddr_st, &size);
    if (ret < 0)
    {
        // If we end up here, it's not because of a too-small buffer, 
        // because sockaddr_storage is the largest possible one.
        return ret;
    }


    /* TODO: AF_INET6 is not necessarily 10, this debug print is wrong */
    if (sockaddr_st.ss_family <= 10) {
        show_msg(MSGDEBUG, "Address family is %s\n", afs[sockaddr_st.ss_family]);
    }

    if (sockaddr_st.ss_family == AF_INET6)
    {
        struct sockaddr_in6 realpeer;
        socklen_t realpeerlen = sizeof(realpeer);
        memcpy(&realpeer, &sockaddr_st, realpeerlen);

        if ((!memcmp(&realpeer.sin6_addr, &ipv4mapped, NAT64PREFIXLEN)) || (check_prefix(config, &realpeer.sin6_addr)))
        {
            struct sockaddr_in result;
            memset(&result, 0, sizeof(result));

            result.sin_family = AF_INET;
            result.sin_port = realpeer.sin6_port;
            memcpy(&result.sin_addr, &realpeer.sin6_addr.s6_addr[12], sizeof(struct in_addr));

            // Copy up to *__len bytes into the available space.
            memcpy(__addr, &result, *__len);

            *__len = sizeof(struct sockaddr_in);
            return ret;
        }
        else {
            // Not sure what the best data to return here would be. 
            // This should never happen in normal operation, though. 
            // This would only be executed if the socket was connected to an IPv6 address 
            // that's not part of a NAT64 prefix.

            // Might be a useful feature for the future - if an application is connecting
            // to a given IPv4 address but you know the server also has an IPv6 without NAT64
            // maybe there can be config entries mapping a given IPv4 to a given IPv6 address. 
            // Unless that's out of scope for this project ...

            // For the meantime, maybe return some of the reserved IPv4's in 240/4?

            show_msg(MSGWARN, "How does this happen?\n");
        }
    }

    // Not IPv6, return original result
    show_msg(MSGDEBUG, "Returning original values\n");
    memcpy(__addr, &sockaddr_st, *__len);
    *__len = size;

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

    /* If we haven't initialized yet, do it now */
    get_config();

    show_msg(MSGDEBUG, "Got getsockname call for socket %d\n", __fd);

    int sock_flags = get_custom_fd_flags(__fd);

    if (sock_flags < 0) {
        show_msg(MSGERR, "Failed to query socket flags for fd %d, err=%d\n", __fd, sock_flags);
        // Assume it's a normal socket, though this should never happen.
        sock_flags = 0;
    }

    if (sock_flags >= 0 && (!(sock_flags & TNAT_FLAG_SOCK_UPGRADED_TO_IPV6))) {
        // TNAT_FLAG_SOCK_UPGRADED_TO_IPV6 is not set - this means that whatever
        // that socket is, we don't care, it's not something we need to modify.
        // So we can call the original getsockname.
        show_msg(MSGDEBUG, "None of our modded sockets, call real getsockname\n");
        return realgetsockname(__fd, __addr, __len);
    }


    /* The software calling getsockname is expecting an IPv4 response. 
    This means that the __addr pointer might only have space for a sockaddr_in, 
    not for a sockaddr_in6. It's probably unreasonable to expect the calling
    application to provide a buffer large enough for an IPv6 sockaddr_in6
    if they're assuming they talk IPv4. So, better allocate our own buffers, temporarily. */

    struct sockaddr_storage sockaddr_st;
    socklen_t size = sizeof(sockaddr_st);
    int ret = realgetsockname(__fd, (struct sockaddr *)&sockaddr_st, &size);
    if (ret < 0) {
        // If we end up here, it's not because of a too-small buffer, 
        // because sockaddr_storage is the largest possible one.
        show_msg(MSGDEBUG, "realgetsockname(%d) returned %d\n", __fd, ret);
        return ret;
    }   

    /* TODO: AF_INET6 is not necessarily 10, this debug print is wrong */
    if (sockaddr_st.ss_family <= 10) {
        show_msg(MSGDEBUG, "Address family is %s\n", afs[sockaddr_st.ss_family]);
    }

    if (sockaddr_st.ss_family == AF_INET6)
    {

        struct sockaddr_in6 realsock;
        socklen_t realsocklen = sizeof(realsock);
        memcpy(&realsock, &sockaddr_st, realsocklen);

        if ((!memcmp(&realsock.sin6_addr, &ipv4mapped, NAT64PREFIXLEN)) || (check_prefix(config, &realsock.sin6_addr)))
        {
            struct sockaddr_in result;
            memset(&result, 0, sizeof(result));

            result.sin_family = AF_INET;
            result.sin_port = realsock.sin6_port;
            memcpy(&result.sin_addr, &realsock.sin6_addr.s6_addr[12], sizeof(struct in_addr));
            
            // Copy up to *__len bytes into the available space.
            int memcpy_size = *__len;
            if (memcpy_size > sizeof(struct sockaddr_in)) {
                memcpy_size = sizeof(struct sockaddr_in);
            }

            memcpy(__addr, &result, memcpy_size);
            *__len = sizeof(struct sockaddr_in);
            return ret;
        }
        else {
            // Application called getsockname, but the socket is not listening on an IPv6-mapped address. 
            // The socket is listening on a "real" IPv6 address. 
            // Returning that address to the application as-is is going to cause issues. 
            // It's probably better to make the application believe it is bound to the unspecific address, 
            // i.e. return an IPv4 address of 0.0.0.0 in this case. 

            struct sockaddr_in result; 
            memset(&result, 0, sizeof(result));

            result.sin_family = AF_INET;
            result.sin_port = realsock.sin6_port;
            result.sin_addr.s_addr = 0;

            int memcpy_size = *__len;
            if (memcpy_size > sizeof(struct sockaddr_in)) {
                memcpy_size = sizeof(struct sockaddr_in);
            }

            show_msg(MSGDEBUG, "Returning fake IPv4 0.0.0.0 as sockname\n");

            memcpy(__addr, &result, memcpy_size);
            *__len = sizeof(struct sockaddr_in);
            return ret;
        }

    }

    // Not IPv6, return original result
    show_msg(MSGDEBUG, "Returning original values\n");
    memcpy(__addr, &sockaddr_st, *__len);
    *__len = size;

    return ret;
}

